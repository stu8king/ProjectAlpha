from django import template

register = template.Library()


@register.filter(name='score_color')
def score_color(score):
    if score <= 4:
        return "green-bg"
    elif 4 < score <= 7:
        return "yellow-bg"
    else:
        return "red-bg"


@register.filter(name='get_item')
def get_item(dictionary, key):
    return dictionary.get(key)


@register.filter
def zip_lists(a, b):
    return zip(a, b)
