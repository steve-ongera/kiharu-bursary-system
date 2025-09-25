from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include("kiharu_system.urls")),
]

# Serve media and static files during development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)


# Custom error handlers (if any)
from django.conf.urls import handler400, handler403, handler404, handler500

handler400 = 'kiharu_system.views.custom_bad_request'
handler403 = 'kiharu_system.views.custom_permission_denied'
handler404 = 'kiharu_system.views.custom_page_not_found'
handler500 = 'kiharu_system.views.custom_server_error'

