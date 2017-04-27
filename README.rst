Storage load test
-----------------

To run it::

    $ virtualenv .
    $ bin/pip install -r requirements.txt
    $ bin/molotov --max-runs 5 -cxv loadtest.py
