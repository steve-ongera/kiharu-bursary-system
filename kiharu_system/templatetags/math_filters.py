from django import template

register = template.Library()

@register.filter
def sub(value, arg):
    """Subtract arg from value"""
    try:
        return float(value) - float(arg)
    except (ValueError, TypeError):
        return ''

@register.filter
def div(value, arg):
    """Divide value by arg"""
    try:
        return float(value) / float(arg) if float(arg) != 0 else 0
    except (ValueError, TypeError, ZeroDivisionError):
        return ''

@register.filter
def mul(value, arg):
    """Multiply value by arg"""
    try:
        return float(value) * float(arg)
    except (ValueError, TypeError):
        return ''

@register.filter
def sum_attribute(queryset, attr):
    """
    Sum a numeric attribute across all objects in a queryset or list
    Usage: {{ queryset|sum_attribute:"amount_requested" }}
    """
    try:
        return sum(getattr(obj, attr, 0) or 0 for obj in queryset)
    except Exception:
        return 0
