from django import template

register = template.Library()


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
