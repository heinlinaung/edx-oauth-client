from logging import getLogger

from django.contrib.auth.models import User
from social_core.pipeline.partial import partial
from openedx.core.djangoapps.user_authn.views.register import create_account_with_params
# from common.djangoapps import third_party_auth
# from third_party_auth.pipeline import (AuthEntryError, make_random_password)
# from common.djangoapps.third_party_auth.pipeline import (AuthEntryError, make_random_password)

log = getLogger(__name__)


@partial.partial
def ensure_user_information(
        strategy, auth_entry, backend=None, user=None, social=None, allow_inactive_user=False, *args, **kwargs
):
    """
    Ensure that we have the necessary information about a user to proceed with the pipeline.

    Either an existing account or registration data.
    """

    data = {}
    try:
        if 'data' in kwargs['response']:
            user_data = kwargs['response']['data'][0]
        else:
            user_data = kwargs['response']
        log.info('Get user data: %s', str(user_data))
        access_token = kwargs['response']['access_token']

        country = user_data.get('country')
        if not country:
            log.info('No country in response.')
        print('GGWP mappppp user_data')
        # Received fields could be pretty different from the expected, mandatory are only 'username' and 'email'
        data['username'] = user_data.get('name')
        data['first_name'] = user_data.get('given_name')
        data['last_name'] = user_data.get('family_name')
        data['email'] = user_data.get('email')
        data['country'] = country
        data['access_token'] = access_token
        if any((data['first_name'], data['last_name'])):
            data['name'] = '{} {}'.format(['first_name'], data['last_name']).strip()
        else:
            data['name'] = user_data.get('username')
    except Exception as e:
        log.exception(e)

    if not user:
        request = strategy.request
        data['terms_of_service'] = "True"
        data['honor_code'] = 'True'
        data['password'] = 'helloworld'

        data['provider'] = backend.name

        try:
            user = User.objects.get(email=data['email'])
        except User.DoesNotExist:
            create_account_with_params(request, data)
            user.is_active = True
            user.save()

    return {'user': user}
