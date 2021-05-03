# Generated by Django 3.0.2 on 2021-04-23 00:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('oidc_provider', '0026_client_multiple_response_types'),
    ]

    operations = [
        migrations.CreateModel(
            name='Scope',
            fields=[
                ('scope', models.CharField(max_length=30, primary_key=True, serialize=False, verbose_name='Scope')),
                ('description', models.CharField(max_length=50)),
            ],
            options={
                'verbose_name': 'Scope',
                'verbose_name_plural': 'Scopes',
            },
        ),
        migrations.RemoveField(
            model_name='client',
            name='_scope',
        ),
        migrations.AddField(
            model_name='client',
            name='scope',
            field=models.ManyToManyField(blank=True, default=None, help_text='Specifies the authorized scope values for the client app.', to='oidc_provider.Scope', verbose_name='Scopes'),
        ),
    ]