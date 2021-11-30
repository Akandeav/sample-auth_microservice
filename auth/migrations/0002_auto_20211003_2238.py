# Generated by Django 3.2.5 on 2021-10-03 22:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('phisAuth', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='userdata',
            name='user_verification',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='userdata',
            name='UserRole',
            field=models.CharField(choices=[('P', 'public'), ('A', 'author'), ('R', 'reviewer')], default='P', max_length=2),
        ),
    ]
