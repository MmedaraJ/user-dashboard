from __future__ import unicode_literals
from email import message
from django.db import models
from django.db.models.fields import CharField
import re, bcrypt

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

class UserManager(models.Manager):
    def registration_validations(self, post_data):
        errors={}
        first_name = self.validate_first_name(post_data, errors)
        last_name = self.validate_last_name(post_data, errors)
        email = self.validate_email(post_data, errors)
        password = self.validate_password(post_data, errors)
        confirm_password = self.validate_password_confirmation(post_data, errors)
        return {**first_name, **last_name, **email, **password, **confirm_password}

    def validate_first_name(self, post_data, errors):
        if len(post_data['first_name']) < 1:
            errors['first_name'] = "First name cannot be empty"
        elif len(post_data['first_name']) < 2:
            errors['first_name'] = "First name must contain at least two letters"
        else: 
            for s in post_data['first_name']:
                if not s.isalpha() and s!='-':
                    errors['first_name'] = "First name must only include letters or '-'"
                    break
        return errors

    def validate_last_name(self, post_data, errors):
        if len(post_data['last_name']) < 1:
            errors['last_name'] = "Last name cannot be empty"
        elif len(post_data['last_name']) < 2:
            errors['last_name'] = "Last name must contain at least two letters"
        else: 
            for s in post_data['last_name']:
                if not s.isalpha() and s!='-':
                    errors['last_name'] = "Last name must only include letters or '-'"
                    break
        return errors

    def validate_email(self, post_data, errors):
        if len(post_data['email']) < 1:
            errors['email'] = "Email cannot be empty"
        elif not EMAIL_REGEX.match(post_data['email']):
            errors['email'] = 'Invalid email address'
        return errors

    def validate_password(self, post_data, errors):
        if len(post_data['password']) < 1:
            errors['password'] = "Password cannot be empty"
        elif len(post_data['password']) < 9:
            errors['password'] = "Password must contain more than 8 characters"
        else:
            up = False
            num = False
            for s in post_data['password']:
                if s.isupper(): up = True
                if s.isdigit(): num = True
            if not up:
                errors['password'] = "Password must contain at least one uppercase letter"
            elif not num:
                errors['password'] = "Password must contain at least one numerical value"
        return errors
            
    def validate_password_confirmation(self, post_data, errors):
        if len(post_data['confirm_password']) < 1:
            errors['confirm'] = "Confirm password cannot be empty"
        elif post_data['confirm_password'] != post_data['password']:
            errors['confirm'] = "Confirm password is not the same as password"
        return errors

    def signin_validations(self, post_data, user):
        errors={}
        email = self.validate_signin_email(post_data, errors, user)
        password = self.validate_signin_password(post_data, errors, user)
        return {**email, **password}

    def validate_signin_email(self, post_data, errors, user):
        if len(post_data['email']) < 1:
            errors['sign_in_email'] = "Email cannot be empty"
        elif not EMAIL_REGEX.match(post_data['email']) or len(user)<1:
            errors['sign_in_email'] = 'Invalid email address'
        else:
            if not user: 
                errors['sign_in_email'] = 'Invalid email address'
        return errors

    def validate_signin_password(self, post_data, errors, user):
        if len(post_data['password']) < 1:
            errors['sign_in_password'] = "Password cannot be empty"
        else:
            if len(user)>0:
                if not bcrypt.checkpw(post_data['password'].encode(), user[0].password_hash.encode()): 
                    errors['sign_in_password'] = "Incorrect password"
        return errors

class User(models.Model):
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    email = models.EmailField()
    password_hash = models.CharField(max_length=255)
    level = models.IntegerField()
    description = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = UserManager()

class MessageManager(models.Manager):
    def validate_message(self, post_data):
        errors = {}
        if len(post_data['new_message']) < 1:
            errors['new_message'] = "Message cannot be empty"
        return errors

class Message(models.Model):
    sender = models.ForeignKey(User, related_name="message_sent")
    receiver = models.ForeignKey(User, related_name="message_received")
    message = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = MessageManager()

class CommentsManager(models.Manager):
    def validate_comment(self, post_data):
        errors = {}
        if len(post_data['new_comment']) < 1:
            errors['new_comment'] = "Comment cannot be empty"
        return errors

class Comments(models.Model):
    sender = models.ForeignKey(User, related_name="comment")
    message = models.ForeignKey(Message, related_name="message_comment")
    comment = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    objects = CommentsManager()