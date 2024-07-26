from django.urls import path, re_path
from .api import vuln_fix_view, vuln_api_view, vuln_no_fix, vuln_for_severity, register, loguin, profile

urlpatterns = [
    path('vuln/',vuln_fix_view,name='vulnerability'),
    path('vuln_api/',vuln_api_view,name='vulnerability_api'),
    path('vuln_nofix/',vuln_no_fix,name='vulnerability_no_fix'),
    path('vuln_severity/<str:severity>',vuln_for_severity,name='vuln_for_severity'),
    re_path('login', loguin),
    re_path('register', register),
    re_path('profile', profile),
]
