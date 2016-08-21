import marshal
import random
import argparse
import textwrap

class DumbByteArrayFuzzer:

    def __init__(self, data, seed = 1, min_ratio = 0.01, max_ratio = 0.05,
                 start_test = 0, ignored_bytes = ()):
        self.__start_test = start_test
        self.__data = data
        self.__seed = seed
        self.__min_bytes = round(min_ratio * len(data));
        self.__max_bytes = round(max_ratio * len(data));
        self.__ignored_bytes = ignored_bytes
        self.reset()

    def reset(self):
        self.__test = self.__start_test
        self.__random = random.Random()
        self.__random_n = random.Random()
        self.__random_position = random.Random()
        self.__random_byte = random.Random()

    def next(self):
        fuzzed = bytearray(self.__data)
        self.__random.seed(self.__seed * self.__test)
        seed = self.__random.random()
        if self.__min_bytes == self.__max_bytes:
            n = self.__min_bytes
        else:
            self.__random_n.seed(seed)
            n = self.__random_n.randrange(self.__min_bytes, self.__max_bytes)
        self.__random_position.seed(seed)
        self.__random_byte.seed(seed)
        i = 0
        while (i < n):
            pos = self.__random_position.randint(0, len(fuzzed) - 1)
            if self.__isignored(fuzzed[pos]):
                continue
            b = self.__random_byte.randint(0, 255)
            print('data[{0:d}] = {1:d}'.format(pos, b))
            fuzzed[pos] = b
            i += 1
        self.__test += 1
        return bytes(fuzzed)

    def __isignored(self, symbol):
        return symbol in self.__ignored_bytes

def print_hex(msg, data):
    hex_data =' '.join('{:02x}'.format(b) for b in data)
    indent = ' ' * 4
    wrapper = textwrap.TextWrapper(
        initial_indent=indent, subsequent_indent=indent, width=70)
    print(msg)
    print(wrapper.fill(hex_data))

parser = argparse.ArgumentParser()
parser.add_argument('--verbose', help='more logs', action='store_true',
                    default=False)
parser.add_argument('--seed', help='seed for pseudo-random generator', type=int,
                    default=1)
parser.add_argument('--test',
                    help='test range, it can be a number, or an interval "start:end"')
parser.add_argument('--ratio',
                    help='fuzzing ratio range, it can be a number, or an interval "start:end"',
                    default='0.05')
args = parser.parse_args()

seed = args.seed

if args.test:
    parts = args.test.split(':')
    if len(parts) == 1:
        start_test = int(parts[0])
        end_test = start_test
    elif len(parts) == 2:
        start_test = int(parts[0])
        if parts[1] == '' or parts[1] == 'infinite':
            end_test = float('inf')
        else:
            end_test = int(parts[1])
    else:
        raise Exception('Could not parse --test value, too many colons')
else:
    start_test = 0
    end_test = float('inf')

parts = args.ratio.split(':')
if len(parts) == 1:
    min_ratio = float(parts[0])
    max_ratio = min_ratio
elif len(parts) == 2:
    min_ratio = float(parts[0])
    max_ratio = float(parts[1])
else:
    raise Exception('Could not parse --ratio value, too many colons')

value = (
        "this is a string",
        [1, 2, 3, 4],
        ("more tuples", 1.0, 2.3, 4.5),
        "this is yet another string"
    )

data = marshal.dumps(value)
print_hex('original data:', data)

fuzzer = DumbByteArrayFuzzer(data, seed, min_ratio, max_ratio, start_test);
test = start_test
while (test <= end_test):
    print('test: {0:d}'.format(test))
    fuzzed = fuzzer.next()
    print_hex('fuzzed data:', fuzzed)
    try:
        redata = marshal.loads(fuzzed)
    except EOFError as err:
        print('EOFError: ' ,err)
    except ValueError as err:
        print('ValueError: ' ,err)
    except TypeError as err:
        print('TypeError: ' ,err)
    except:
        print('Unexpected error')
        raise

    test += 1
