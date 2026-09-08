import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

exec(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
          'app', 'dashboard', 'home.py')).read())