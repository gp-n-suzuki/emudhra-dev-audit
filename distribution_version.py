"""Single source for distribution identity; independent of report schemas."""
VERSION = '1.0.1'
DISPLAY_VERSION = VERSION[:-2] if VERSION.endswith('.0') else VERSION
TAG = 'v' + VERSION


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--display', action='store_true')
    parser.add_argument('--tag', action='store_true')
    args = parser.parse_args()
    print(TAG if args.tag else DISPLAY_VERSION if args.display else VERSION)
