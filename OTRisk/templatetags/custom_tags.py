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
