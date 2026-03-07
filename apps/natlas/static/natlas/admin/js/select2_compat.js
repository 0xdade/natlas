"use strict";

// jquery.init.js calls jQuery.noConflict(true), removing jQuery from global
// scope and placing it at django.jQuery. Select2's UMD wrapper falls back to
// window.jQuery, which is now gone. Re-expose it so Select2 can initialize.
if (!window.jQuery && window.django && django.jQuery) {
    window.jQuery = django.jQuery;
}
