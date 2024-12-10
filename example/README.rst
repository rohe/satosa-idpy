########################################
OpenID federation as Identity Federation
########################################

The federation consists of the following entities:

* trust anchor
* trust mark issuer
* OpenID Connect Provider
* OpenID Relying Party

In this example all the entities are running on the same machine.
It is of course not necessary to do so.
If you run the entities on separate machines you have to move the necessary
files inbetween them. You also have to change **entity_id**, **port** and **domain**
in the relevant conf.json file.

Start by setting up the trust anchor.

Trust Anchor
============

The configuration of the trust anchor can be found in the *trust_anchor* directory.
Consists of two files

* conf.json
    The configuration of the entitys components
* views.py
    The webserver's (Flask) interface configuration

The existence of those two file with exactly those names are necessary for this
to work.

To start running the trust anchor you have to do::

    ./entity.py trust_anchor

This will create a number of things in the *trust_anchor* directory

* private
    Where the JWKS representation of the private federation keys are kept
* static
    Where the JWKS representation of the public federation keys are kept
* subordinate
    A directory where information about subordinates are to be kept
* trust_mark_issuers
    A directory where information about trust mark issuers are kept.
* debug.log
    A log file

All entities in the federation has to have some information about the
trust mark. The information to pass along is collected by doing::

    ./get_info.py -k -t https://127.0.0.1:7003 > trust_anchor.json

This must be done while the Trust anchor is running.
Of course if you have changed the entity_id of the trust anchor from
https://127.0.0.1:7003 to something else you have to change this command accordingly.

Now you're done with phase 1 concerning the trust anchor. So you can
kill that process for the time being.

Trust Mark Issuer
=================

To start running the trust mark issuer you have to do::

    ./entity.py trust_mark_issuer

A slightly different set of files/directories has been added

* private
    Where the JWKS representation of the private federation keys are kept
* static
    Where the JWKS representation of the public federation keys are kept
* trust_anchors
    A directory where information about trust anchors are kept
* authority_hints
    A file containing entity_ids of this entity's authority hints.
    Note that there is also a authority_hints.lock file present you can safely
    ignore it.
* debug.log
    A log file

Now four things have to happen::

1. Adding information about trust anchors
2. Add authority hints
3. Add information about the trust mark issuer as a subordinate to the trust anchor
4. Add information about the trust mark issuer as a trust mark issuer to the trust anchor.

The first two are simply::

    ./add_info.py -s trust_anchor.json -t trust_mark_issuer/trust_anchors
    echo -e "https://127.0.0.1:7003" >> trust_mark_issuer/authority_hints

The third would look like this::

    ./get_info.py -k -s https://127.0.0.1:6010 > tmp.json
    ./add_info.py -s tmp.json -t trust_anchor/subordinates

The fourth is presently done like this (may change in the future)::

    ./issuer.py trust_mark_issuer > tmp.json
    ./add_info.py -s tmp.json -t trust_anchor/trust_mark_issuers

That should do it for the trust mark issuer.
If you now restart it it should have all the necessary information to be part of the federation.

**Note** The same goes for these commands as was noted above. If you change the
entity_id of the trust anchor or the trust mark issuer you have to change the
command parameters accordingly.


OpenID Relying Party
====================

Much the same as for the openid relying party.
To start running the relying party you have to do::

    ./entity.py relying_party_explicit

A slightly different set of files/directories has been added

* private
    Where the JWKS representation of the private federation keys are kept
* static
    Where the JWKS representation of the public federation keys are kept
* trust_anchors
    A directory where information about trust anchors are kept
* authority_hints
    A file containing entity_ids of this entity's authority hints.
    Note that there is also a authority_hints.lock file present you can safely
    ignore it.
* debug.log
    A log file

Now four things have to happen::

1. Adding information about trust anchors
2. Add authority hints
3. Add information about the wallet provider as a subordinate to the trust anchor

The first two are simply::

    ./add_info.py -s trust_anchor.json -t relying_party_explicit/trust_anchors
    echo -e "https://127.0.0.1:7003" >> relying_party_explicit/authority_hints

The third would look like this::

    ./get_info.py -k -s https://127.0.0.1:4010 > tmp.json
    ./add_info.py -s tmp.json -t trust_anchor/subordinates


That should do it for the openid relying party.
If you now restart it it should have all the necessary information to be part of the federation.

**Note** The same goes for these commands as was noted above. If you change the
entity_id of the trust anchor or the wallet provider you have to change the
command parameters accordingly.

OpenID Connect Provider
=======================

Start with copying plugins/idpyoidc_frontend.original.yaml to plugins/idpyoidc_frontend.yaml .

Trust anchor information
------------------------

The TA's keys can be found in::

    trust_anchor.json

This key set has to be copied into the frontend configuration file::

    satosa_op/plugins/idpyoidc_frontend.yaml

The place where you should copy the key information to looks like this::

    config/op/server_info/trust_anchors:
        <TRUST_ANCHORS>

Note that what you have to put in the yaml file is of course YAML and not JSON.
To facilitate this there is a small script you can use::

    ./convert_json_to_yaml.py trust_anchor.json

Replace <TRUST_ANCHORS> with the output from the script above.

If the entity has some trust marks these should be copy those into the place marked::

    config/op/server_info/trust_marks:
        <TRUST_MARKS>

If there are no trust marks remove those two lines.

And lastly the authority hints. These should be placed here::

    config/op/server_info/authority_hints:
        <AUTHORITY_HINTS>

Adding the OP as a subordinate to the trust anchor
--------------------------------------------------

If you start the credential issuer once it will create its keys and place copies of them in certain files.
The file you have to look for is **public/fed_keys.json**. In it you should have the needed information.
Use the file **subordinate_info.json** as a model and replace::

    {
      "keys": []
    }

with what you find in the fed_keys file.
Here I copied subordinate_info.json into op_info.json and modified the copy.

Make sure you are in the example directory and then run::

    ./add_info.py -s satosa_op/op_info.json -t trust_anchor/subordinates


OpenID Connect Relying party
============================

Much the same as for the openid relying party.
To start running the relying party you have to do::

    ./entity.py relying_party_explicit

A slightly different set of files/directories has been added

* private
    Where the JWKS representation of the private federation keys are kept
* static
    Where the JWKS representation of the public federation keys are kept
* trust_anchors
    A directory where information about trust anchors are kept
* authority_hints
    A file containing entity_ids of this entity's authority hints.
    Note that there is also a authority_hints.lock file present you can safely
    ignore it.
* debug.log
    A log file

Now four things have to happen::

1. Adding information about trust anchors
2. Add authority hints
3. Add information about the wallet provider as a subordinate to the trust anchor

The first two are simply::

    ./add_info.py -s trust_anchor.json -t relying_party_explicit/trust_anchors
    echo -e "https://127.0.0.1:7003" >> relying_party_explicit/authority_hints

The third would look like this::

    ./get_info.py -k -s https://127.0.0.1:4010 > tmp.json
    ./add_info.py -s tmp.json -t trust_anchor/subordinates


That should do it for the openid relying party.
If you now restart it it should have all the necessary information to be part of the federation.

**Note** The same goes for these commands as was noted above. If you change the
entity_id of the trust anchor or the wallet provider you have to change the
command parameters accordingly.

Creating a trust mark for an entity
===================================

If the OP should have any trust marks you can use this pattern.

For this the script *create_trust_mark.py* is included.
Typical usage::

    ./create_trust_mark.py -d trust_mark_issuer -m https://example.org/foobar -e https://127.0.0.1:8080
     > trust_mark.8080


usage: create_trust_mark.py [-h] [-d DIR_NAME] [-e ENTITY_ID] [-m TRUST_MARK_ID] ::

    options:
      -h, --help            show this help message and exit
      -d DIR_NAME, --dir_name DIR_NAME The directory of the trust mark issuer
      -e ENTITY_ID, --entity_id ENTITY_ID The target of the Trust Mark
      -m TRUST_MARK_ID, --trust_mark_id TRUST_MARK_ID

The trust mark issuer doesn't have to be running for this to work.
Once you have the trust mark drop it in the relying_party_explicit/::

    cp trust_mark.4010 relying_party_explicit/trust_marks

