from django.conf.urls import url
from . import views

urlpatterns = [
    url(r'^$', views.index, name='index'),
    url(r'^users/new/$', views.new, name='new'),
    url(r'^signin/$', views.signin, name='signin'),
    url(r'^logoff/$', views.logoff, name='logoff'),
    url(r'^users/edit/$', views.profile, name='profile'),
    url(r'^register/$', views.register, name='register'),
    url(r'^dashboard/$', views.dashboard, name='dashboard'),
    url(r'^dashboard/$', views.dashboard, name='dashboard'),
    url(r'^remove/(?P<id>\d+)$', views.remove, name='remove'),
    url(r'^create_user/$', views.create_user, name='create_user'),
    url(r'^process_start/$', views.process_start, name='process_start'),
    url(r'^users/edit/(?P<id>\d+)$', views.edit_user, name='edit_user'),
    url(r'^users/show/(?P<id>\d+)$', views.show_user, name='show_user'),
    url(r'^process_signin/$', views.process_signin, name='process_signin'),
    url(r'^update_user/(?P<id>\d+)$', views.update_user, name='update_user'),
    url(r'^new_message/(?P<id>\d+)$', views.new_message, name='new_message'),
    url(r'^dashboard/admin/$', views.dashboard_admin, name='dashboard_admin'),
    url(r'^process_dashboard/$', views.process_dashboard, name='process_dashboard'),
    url(r'^update_password/(?P<id>\d+)$', views.update_password, name='update_password'),
    url(r'^process_registration/$', views.process_registration, name='process_registration'),
    url(r'^update_description/(?P<id>\d+)$', views.update_description, name='update_description'),
    url(r'^update_user_profile/(?P<id>\d+)$', views.update_user_profile, name='update_user_profile'),
    url(r'^new_comment/(?P<message_id>\d+)/(?P<user_id>\d+)$', views.new_comment, name='new_comment'),
    url(r'^update_password_profile/(?P<id>\d+)$', views.update_password_profile, name='update_password_profile')
]