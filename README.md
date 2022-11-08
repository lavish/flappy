Flappy Flag
===========
Flap flap flap alarm clock Obama.

Simple, standalone & hackable exploit execution toolkit. Useful when everything else fails or if you
need a local exploit runner to chain with other components as part of a larger attack infrastructure.


Install
-------
An up-to-date Python 3 installation is all you need to run flappy. It should be enough to 
create a virtualenv as follows:

    $ python3 -m venv  ~/.flappy_venv
    $ . ~/.flappy_venv/bin/activate
    (.flappy_venv) $ pip install -r requirements.txt


Usage
-----
Run `flappy.py -h` for a complete list of parameters. Usage example:

    (.flappy_venv) $ ./flappy.py -x ../exploits/cookie.py -ip 10.10.1.1 -s Bl0g -v

Exploit templates can be found under the `exploits/` directory.

Exploits are always executed with the following 2 parameters, followed by an optional list of flag
ids, in this order:

    ip, team_id, [flag_ids...]

For instance:

| ip        | team id | flag id #1    | flag id #2    | flag id #3    |
|-----------|---------|---------------|---------------|---------------|
| 10.10.6.1 | 6       | user-ng0hbTHg | user-u1Gr28NV | user-LLQ4mwMW |

If your exploit does not need a team id or any of the provided flag ids, it's safe to just ignore
them.


History & Credits
-----------------
Flappy was initially developed by Marco Squarcina back in 2014 for the 
[c00kies@venice](https://ctftime.org/team/1752/) team, with support and further contributions from
Marco Gasparini, Claudio Bozzato, and Lorenzo Veronese. The tool served as the exploit runner for
[mhackeroni](https://ctftime.org/team/57788/) and it is now maintained as the *local attacker
component* in the [WE_0WN_Y0U](https://ctftime.org/team/1964/) infrastructure. This is a 
stripped-down version of the main tool, including only the local executor for improved hackability.