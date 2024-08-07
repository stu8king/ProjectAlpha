from django import template
import json

register = template.Library()


@register.filter(name='get_item')
def get_item(dictionary, key):
    return dictionary.get(key)
@register.filter
def zip_lists(a, b):
    return zip(a, b)


@register.filter
def currency_format(value):
    if value >= 1000000:
        return f"${value / 1000000:.2f}M"
    elif value >= 1000:
        return f"${value / 1000:.2f}K"
    else:
        return f"${value}"


@register.filter
def getattr(obj, attr_name):
    """Get an attribute of an object dynamically."""
    return getattr(obj, attr_name)


@register.filter(name='to_int')
def to_int(value):
    try:
        return int(value.strip('%'))
    except ValueError:
        return 0


@register.filter
def jsonify(value):
    return json.loads(value)


@register.filter(name='split')
def split(value, arg):
    return value.split(arg)


@register.filter(name='remove_duplicates')
def remove_duplicates(queryset):
    return queryset.distinct()


@register.filter
def add_unique_item(queryset, item):
    if item not in queryset:
        queryset.append(item)
    return queryset


@register.filter(name='get_unique_values')
def get_unique_values(queryset, field_name):
    return queryset.order_by(field_name).values_list(field_name, flat=True).distinct()


from django import template

register = template.Library()


@register.filter
def impact_level(value):
    mapping = {
        1: 'Low',
        2: 'Low',
        3: 'Low/Med',
        4: 'Low/Med',
        5: 'Med',
        6: 'Med',
        7: 'Med / High',
        8: 'Med / High',
        9: 'High',
        10: 'High'
    }
    return mapping.get(value, 'Unknown')


@register.filter
def mul(value, arg):
    return value * arg


@register.filter(name='multiply')
def multiply(value, arg):
    return value * arg


@register.filter
def start_index(value, arg):
    return value * arg


@register.filter
def end_index(value, arg):
    return (value + 1) * arg


@register.filter(name='add_class')
def add_class(field, css):
    return field.as_widget(attrs={"class": css})