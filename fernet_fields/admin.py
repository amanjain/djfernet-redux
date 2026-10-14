"""Opt-in admin display protection for encrypted fields."""
from .fields import EncryptedField


class MaskedEncryptedAdminMixin:
    """Exclude encrypted edit fields and replace named displays with a constant.

    Place this before ModelAdmin in the inheritance list. Custom display methods,
    exports and other views must enforce their own permissions; this mixin does
    not make decrypted model attributes inaccessible to application code.
    """

    def _masked_fields(self):
        if '_fernet_masked_fields' in self.__dict__:
            return self.__dict__['_fernet_masked_fields']
        mapping = {}
        for field in self.model._meta.concrete_fields:
            if not isinstance(field, EncryptedField):
                continue
            name = '_masked_' + field.name
            # Avoid both model attributes and pre-existing admin callbacks.
            while hasattr(self.model, name) or hasattr(self, name):
                name += '_'
            mapping[field.name] = name

            def display(obj):
                # Do not read the field, even if its ciphertext is unreadable.
                return '********'
            display.short_description = field.verbose_name
            setattr(self, name, display)
        self.__dict__['_fernet_masked_fields'] = mapping
        return mapping

    def get_exclude(self, request, obj=None):
        excluded = list(super().get_exclude(request, obj) or ())
        return tuple(excluded + [name for name in self._masked_fields() if name not in excluded])

    def get_readonly_fields(self, request, obj=None):
        mapping = self._masked_fields()
        names = [mapping.get(name, name) if isinstance(name, str) else name
                 for name in super().get_readonly_fields(request, obj)]
        return tuple(names + [name for name in mapping.values() if name not in names])

    def get_list_display(self, request):
        mapping = self._masked_fields()
        return tuple(mapping.get(name, name) if isinstance(name, str) else name
                     for name in super().get_list_display(request))

    def get_fieldsets(self, request, obj=None):
        mapping = self._masked_fields()

        def mask_layout(value):
            if isinstance(value, (tuple, list)):
                return tuple(mask_layout(item) for item in value)
            return mapping.get(value, value)

        return [(title, dict(options, fields=mask_layout(options['fields'])))
                for title, options in super().get_fieldsets(request, obj)]
