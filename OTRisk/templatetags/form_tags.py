from django import template

register = template.Library()


@register.filter(name='add_class')
def add_class(value, arg):
    css_classes = value.field.widget.attrs.get('class', '')
    css_classes = f"{css_classes} {arg}".strip()
    return value.as_widget(attrs={'class': css_classes})
