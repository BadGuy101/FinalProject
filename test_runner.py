import unittest
import sys

def run_tests():
    # Discover all tests in the tests directory
    loader = unittest.TestLoader()
    suite = loader.discover('tests', pattern='test_*.py')
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Exit with proper status code
    sys.exit(not result.wasSuccessful())

if __name__ == '__main__':
    run_tests()