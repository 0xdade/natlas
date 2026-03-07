"use strict";

(function () {
    function initTagSelects() {
        django.jQuery("select.tag-select").select2({
            tags: true,
            tokenSeparators: [","],
            placeholder: "Select or create tags\u2026",
            width: "20em",
        });
    }

    django.jQuery(document).ready(initTagSelects);
})();
