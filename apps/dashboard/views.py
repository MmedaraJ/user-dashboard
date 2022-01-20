from xml.etree.ElementTree import Comment
from django.shortcuts import redirect, render
from django.contrib import messages
from .models import Message, User, Comments
from django.core.urlresolvers import reverse
import re, bcrypt

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

def index(request):
    return render(request, 'dashboard/welcome.html')

def signin(request):
    return render(request, 'dashboard/signin.html')

def process_signin(request):
    user = None
    errors = {}
    if len(request.POST['email']) > 1:
        user = User.objects.filter(email = request.POST['email'])
        errors = User.objects.signin_validations(request.POST, user)
    else: errors['sign_in_email'] = "Email cannot be empty"
    if len(errors):
        for k, v in errors.items():
            messages.error(request, v, extra_tags=k)
        return redirect(reverse('dashboard:signin'))
    else: 
        if user:
            request.session['user_id'] = user[0].id
            messages.success(request, 'Successful sign in', extra_tags='signin')
            if user[0].level == 9: return redirect(reverse('dashboard:dashboard_admin'))
            else: return redirect(reverse('dashboard:dashboard'))

def register(request):
    return render(request, 'dashboard/register.html')

def process_registration(request):
    errors = User.objects.registration_validations(request.POST)
    if len(errors):
        for k, v in errors.items():
            messages.error(request, v, extra_tags=k)
        return redirect(reverse('dashboard:register'))
    else:
        user_level = 0 if User.objects.count() > 0 else 9
        user_password_hash = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
        user = User(first_name=request.POST['first_name'], last_name=request.POST['last_name'], 
            email=request.POST['email'], password_hash=user_password_hash, level=user_level, description='')
        user.save()
        messages.success(request, f'Congratulations, {request.POST["first_name"]}. You have successfully registered.', extra_tags='registration')
        request.session['user_id'] = user.id
        if user_level == 9: return redirect(reverse('dashboard:dashboard_admin'))
        else: return redirect(reverse('dashboard:dashboard'))

def create_user(request):
    if 'user_id' in request.session:
        user = User.objects.get(id=request.session['user_id'])
        if user.level == 9:
            errors = User.objects.registration_validations(request.POST)
            if len(errors):
                for k, v in errors.items():
                    messages.error(request, v, extra_tags=k)
                return redirect(reverse('dashboard:new'))
            else:
                user_level = 0 if User.objects.count() > 0 else 9
                user_password_hash = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
                User.objects.create(first_name=request.POST['first_name'], last_name=request.POST['last_name'], 
                    email=request.POST['email'], password_hash=user_password_hash, level=user_level, description='')
                messages.success(request, 'New user successfully created', extra_tags='create_user')
                return redirect(reverse('dashboard:dashboard_admin'))
        return redirect(reverse('dashboard:dashboard'))
    return redirect(reverse('dashboard:index'))

def dashboard_admin(request):
    if 'user_id' in request.session:
        user = User.objects.get(id=request.session['user_id'])
        if user.level == 9:
            context = {
                'users': User.objects.all()
            }
            return render(request, 'dashboard/dashboard_admin.html', context)
        return redirect(reverse('dashboard:dashboard'))
    return redirect(reverse('dashboard:index'))

def dashboard(request):
    if 'user_id' in request.session:
        user = User.objects.get(id=request.session['user_id'])
        if user.level == 0:
            context = {
                'users': User.objects.all()
            }
            return render(request, 'dashboard/dashboard.html', context)
        elif user.level == 9: return redirect(reverse('dashboard:dashboard_admin'))
    return redirect(reverse('dashboard:index'))
        
def new(request):
    if 'user_id' in request.session:
        user = User.objects.get(id=request.session['user_id'])
        if user.level == 9: return render(request, 'dashboard/new.html')
        return redirect(reverse('dashboard:dashboard'))
    return redirect(reverse('dashboard:index'))

def logoff(request):
    if 'user_id' in request.session: del request.session['user_id']
    return redirect(reverse('dashboard:signin'))

def process_dashboard(request):
    if 'user_id' in request.session:
        user = User.objects.get(id=request.session['user_id'])
        if user.level == 9: return redirect(reverse('dashboard:dashboard_admin'))
        else: return redirect(reverse('dashboard:dashboard'))
    return redirect(reverse('dashboard:index'))

def process_start(request):
    if 'user_id' in request.session:
        user = User.objects.get(id=request.session['user_id'])
        if user.level == 9: return redirect(reverse('dashboard:dashboard_admin'))
        else: return redirect(reverse('dashboard:dashboard'))
    return redirect(reverse('dashboard:signin'))

def edit_user(request, id):
    if 'user_id' in request.session:
        user = User.objects.get(id=request.session['user_id'])
        if user.level == 9:
            if len(User.objects.filter(id=id)) > 0:
                context = {
                    "user": User.objects.get(id=id)
                }
                return render(request, 'dashboard/edit_user.html', context)
            return redirect(reverse('dashboard:dashboard_admin'))
        else: return redirect(reverse('dashboard:dashboard'))
    return redirect(reverse('dashboard:index'))

def update_user(request, id):
    if 'user_id' in request.session:
        user = User.objects.get(id=request.session['user_id'])
        if user.level == 9:
            if len(User.objects.filter(id=id)) > 0:
                user = User.objects.get(id=id)
                errors = {}
                errors_e = User.objects.validate_email(request.POST, errors)
                errors_f = User.objects.validate_first_name(request.POST, errors)
                errors_l = User.objects.validate_last_name(request.POST, errors)
                errors = {**errors_e, **errors_f, **errors_l}
                if len(errors):
                    for k, v in errors.items():
                        messages.error(request, v, extra_tags=k)
                    return redirect(reverse('dashboard:edit_user', kwargs={'id':id}))
                else:
                    user.email = request.POST['email']
                    user.first_name = request.POST['first_name']
                    user.last_name = request.POST['last_name']
                    user_level = request.POST['user_level']
                    level = None
                    if user_level == 'Admin': level = 9
                    elif user_level == 'Normal': level = 0
                    user.level = level
                    user.save()
                    messages.success(request, 'User information successfully updated', extra_tags='update_user')
                    return redirect(reverse('dashboard:edit_user', kwargs={'id':id}))
            return redirect(reverse('dashboard:dashboard_admin'))
        else: return redirect(reverse('dashboard:dashboard'))
    return redirect(reverse('dashboard:index'))

def update_password(request, id):
    if 'user_id' in request.session:
        user = User.objects.get(id=request.session['user_id'])
        if user.level == 9:
            if len(User.objects.filter(id=id)) > 0:
                user = User.objects.get(id=id)
                errors = {}
                errors_p = User.objects.validate_password(request.POST, errors)
                errors_cp = User.objects.validate_password_confirmation(request.POST, errors)
                errors = {**errors_p, **errors_cp}
                if len(errors):
                    for k, v in errors.items():
                        messages.error(request, v, extra_tags=k)
                    return redirect(reverse('dashboard:edit_user', kwargs={'id':id}))
                else:
                    user_password_hash = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
                    user.password_hash = user_password_hash
                    user.save()
                    messages.success(request, 'User password successfully updated', extra_tags='update_password')
                    return redirect(reverse('dashboard:edit_user', kwargs={'id':id}))
            return redirect(reverse('dashboard:dashboard_admin'))
        else: return redirect(reverse('dashboard:dashboard'))
    return redirect(reverse('dashboard:index'))

def profile(request):
    if 'user_id' in request.session:
        context = {
            "user": User.objects.get(id=request.session['user_id'])
        }
        return render(request, 'dashboard/profile.html', context)
    return redirect(reverse('dashboard:index'))

def update_user_profile(request, id):
    if 'user_id' in request.session:
        user = User.objects.get(id=request.session['user_id'])
        if user.level == 9:
            if len(User.objects.filter(id=id)) > 0:
                user = User.objects.get(id=id)
                errors = {}
                errors_e = User.objects.validate_email(request.POST, errors)
                errors_f = User.objects.validate_first_name(request.POST, errors)
                errors_l = User.objects.validate_last_name(request.POST, errors)
                errors = {**errors_e, **errors_f, **errors_l}
                if len(errors):
                    for k, v in errors.items():
                        messages.error(request, v, extra_tags=k)
                    return redirect(reverse('dashboard:profile'))
                else:
                    user.email = request.POST['email']
                    user.first_name = request.POST['first_name']
                    user.last_name = request.POST['last_name']
                    user.save()
                    messages.success(request, 'User information successfully updated', extra_tags='update_user_profile')
                    return redirect(reverse('dashboard:profile'))
            return redirect(reverse('dashboard:dashboard_admin'))
        else: return redirect(reverse('dashboard:dashboard'))
    return redirect(reverse('dashboard:index'))

def update_password_profile(request, id):
    if 'user_id' in request.session:
        user = User.objects.get(id=request.session['user_id'])
        if user.level == 9:
            if len(User.objects.filter(id=id)) > 0:
                user = User.objects.get(id=id)
                errors = {}
                errors_p = User.objects.validate_password(request.POST, errors)
                errors_cp = User.objects.validate_password_confirmation(request.POST, errors)
                errors = {**errors_p, **errors_cp}
                if len(errors):
                    for k, v in errors.items():
                        messages.error(request, v, extra_tags=k)
                    return redirect(reverse('dashboard:profile'))
                else:
                    user_password_hash = bcrypt.hashpw(request.POST['password'].encode(), bcrypt.gensalt())
                    user.password_hash = user_password_hash
                    user.save()
                    messages.success(request, 'User password successfully updated', extra_tags='update_password_profile')
                    return redirect(reverse('dashboard:profile'))
            return redirect(reverse('dashboard:dashboard_admin'))
        else: return redirect(reverse('dashboard:dashboard'))
    return redirect(reverse('dashboard:index'))

def update_description(request, id):
    if 'user_id' in request.session:
        if len(User.objects.filter(id=id)) > 0:
            user = User.objects.get(id=id)
            user.description = request.POST['description']
            user.save()
            messages.success(request, 'User description successfully updated', extra_tags='update_description')
            return redirect(reverse('dashboard:profile'))
        else:
            user = User.objects.get(id=request.session['user_id'])
            if user.level == 9: return redirect(reverse('dashboard:dashboard_admin'))
            else: return redirect(reverse('dashboard:dashboard'))
    return redirect(reverse('dashboard:index'))

def show_user(request, id):
    if 'user_id' in request.session:
        if len(User.objects.filter(id=id)) > 0:
            context = {
                "user": User.objects.get(id=id),
                "messages": Message.objects.filter(receiver__id=id).order_by("-created_at"),
                "comments": Comments.objects.filter(message__receiver__id=id).order_by("created_at")
            }
            return render(request, 'dashboard/show.html', context)
        else:
            user = User.objects.get(id=request.session['user_id'])
            if user.level == 9: return redirect(reverse('dashboard:dashboard_admin'))
            else: return redirect(reverse('dashboard:dashboard'))
    return redirect(reverse('dashboard:index'))

def new_message(request, id):
    if 'user_id' in request.session:
        errors = Message.objects.validate_message(request.POST)
        if len(errors):
            for k, v in errors.items():
                messages.error(request, v, extra_tags=k)
            return redirect(reverse('dashboard:show_user', kwargs={'id':id}))
        else:
            sender = User.objects.get(id=request.session['user_id'])
            receiver = User.objects.get(id=id)
            Message.objects.create(sender=sender, receiver=receiver, message=request.POST['new_message'])
            messages.success(request, "Message sent")
            return redirect(reverse('dashboard:show_user', kwargs={'id':id}))
    return redirect(reverse('dashboard:index'))

def new_comment(request, message_id, user_id):
    if 'user_id' in request.session:
        errors = Comments.objects.validate_comment(request.POST)
        if len(errors):
            for k, v in errors.items():
                messages.error(request, v, extra_tags=k)
            return redirect(reverse('dashboard:show_user', kwargs={'id':user_id}))
        else:
            sender = User.objects.get(id=request.session['user_id'])
            message = Message.objects.get(id=message_id)
            Comments.objects.create(sender=sender, message=message, comment=request.POST['new_comment'])
            messages.success(request, "Comment sent")
            return redirect(reverse('dashboard:show_user', kwargs={'id':user_id}))
    return redirect(reverse('dashboard:index'))

def remove(request, id):
    if 'user_id' in request.session:
        user = User.objects.get(id=request.session['user_id'])
        if user.level == 9:
            User.objects.get(id=id).delete()
            messages.success(request, 'User successfully deleted')
            return redirect(reverse('dashboard:dashboard_admin'))
        return redirect(reverse('dashboard:dashboard'))
    return redirect(reverse('dashboard:index'))