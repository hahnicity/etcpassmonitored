# etcpassmonitored
Monitor /etc/passwd and /etc/shadow for irregularities and security holes.

## Functionality
Monitoring takes on seven checks

 * Ensure all lines in /etc/passwd are correctly formatted
 * Ensure no other user shares the 0 uid with root
 * Check to verify that there is a password placeholder in /etc/passwd for a user
 * Validate that users other than root do not share the same uid with another user
 * Ensure /etc/shadow is correctly formatted
 * Check to see that each user has an encrypted password, and if not at least a placeholder
 * See if there is an expiration date for each user on the system

## Usage
You can use it in a cron job or celery queue if so desired. All that is necessary
is that the user running the job has superuser priviledges (because it needs to
read /etc/shadow). Running the script can be done using `monitor.py`

    ./monitor.py

## Notification modules
Currently there is only one notification module in the form of a logger that writes
to `/var/log/etcpassmonitored.log`. There is the option of writing different notification
modules so long as the notifications API contract of 

    def notify(reason):
        ... code goes here

is maintained. Once a new notification module is written either the `config.py` module
must be updated with the path to the new notification module or a new configuration module
will need to be created and a path set to it using the `ETCPASSMONITORED_CONFIG` envvar.
Inside this module a path to the new notification module must be set using the `NOITIFY_MODULE`
variable like

    NOITIFY_MODULE = "/path/to/my/notification/module.py"

