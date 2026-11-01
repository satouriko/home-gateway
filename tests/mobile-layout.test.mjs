import assert from 'node:assert/strict';
import { test } from 'node:test';
import vm from 'node:vm';
import { installMobileViewport } from '../src/dsh/mobile-layout.mjs';

function page(touch) {
  const properties = new Map([['touch-action', ['auto', '']]]);
  const style = {
    getPropertyValue: key => properties.get(key)?.[0] || '',
    getPropertyPriority: key => properties.get(key)?.[1] || '',
    setProperty: (key, value, priority) => properties.set(key, [value, priority]),
    removeProperty: key => properties.delete(key),
  };
  const media = Object.assign(new EventTarget(), { matches: touch });
  const document = Object.assign(new EventTarget(), { documentElement: { style } });
  const window = { matchMedia: () => media, innerWidth:390 };
  const cleanup = vm.runInNewContext(`(${installMobileViewport.toString()})()`, { window, document });
  return { media, document, style, cleanup };
}

test('touch layout stops page pinch while retaining panning; desktop stays unchanged', () => {
  const mobile = page(true);
  assert.equal(mobile.style.getPropertyValue('touch-action'), 'pan-y');
  const pinch = new Event('gesturestart', { cancelable: true });
  mobile.document.dispatchEvent(pinch);
  assert.equal(pinch.defaultPrevented, true);
  const scroll = new Event('touchmove', { cancelable: true });
  mobile.document.dispatchEvent(scroll);
  assert.equal(scroll.defaultPrevented, false);
  const desktop = page(false);
  assert.equal(desktop.style.getPropertyValue('touch-action'), 'auto');
  const desktopPinch = new Event('gesturestart', { cancelable: true });
  desktop.document.dispatchEvent(desktopPinch);
  assert.equal(desktopPinch.defaultPrevented, false);
});

test('rotation out of the touch layout and disposal restore the original style', () => {
  const scene = page(true);
  scene.media.matches = false;
  scene.media.dispatchEvent(new Event('change'));
  assert.equal(scene.style.getPropertyValue('touch-action'), 'auto');
  scene.media.matches = true;
  scene.media.dispatchEvent(new Event('change'));
  assert.equal(scene.style.getPropertyValue('touch-action'), 'pan-y');
  scene.cleanup();
  assert.equal(scene.style.getPropertyValue('touch-action'), 'auto');
  const event = new Event('gesturechange', { cancelable: true });
  scene.document.dispatchEvent(event);
  assert.equal(event.defaultPrevented, false);
});

test('edge history guard leaves center scrolling and interactive targets native',()=>{
  const scene=page(true);
  const start=x=>{
    const event=new Event('touchstart',{cancelable:true});
    Object.defineProperty(event,'touches',{value:[{clientX:x}]});
    scene.document.dispatchEvent(event);return event.defaultPrevented;
  };
  assert.equal(start(150),false);
  assert.equal(start(10),true);
  scene.document.closest=()=>({});
  assert.equal(start(10),false);
  scene.cleanup();scene.document.closest=()=>null;
  assert.equal(start(10),false);
});
