from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractUser
from django.urls import reverse


class UserManager(BaseUserManager):

    use_in_migrations = True

    def create_user(self, email, password, **extra_fields):
        """
        Create and save a user with the given email and password.
        """
        if not email:
            raise ValueError('The given email must be set')
        user = self.model(email=self.normalize_email(email), **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        """
        Create and save a user with the given email and password.
        """
        user = self.create_user(email, password=password, **extra_fields)
        user.is_staff = True
        user.is_superuser = True
        user.save(using=self.db)
        return user


class User(AbstractUser):
    username = None
    email = models.EmailField('email', unique=True)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()


class Profile(models.Model):
    user = models.OneToOneField(User, null=True, on_delete=models.CASCADE)
    bio = models.CharField(max_length=255, null=True, blank=True)
    ville = models.CharField(max_length=255, null=True, blank=True)
    pays = models.CharField(max_length=255, null=True, blank=True)
    profile_pic = models.ImageField(null=True, blank=True, upload_to="images/profile/")

    def __str__(self):
        return str(self.user)

    def get_absolute_url(self):
        return reverse('home')
