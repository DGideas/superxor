"""
superXOR by DGideas
(c) 2023 dgideas@outlook.com
published under WTFPL, do anything you want!
"""
from abc import ABC, abstractmethod
from argparse import ArgumentParser
from hashlib import sha256
import logging
import os, os.path
from typing import Dict

logging.basicConfig(format="%(message)s", level=logging.INFO)
logger = logging.getLogger("superxor")

BLOCK_SIZE = 64 * 1024 # 64 kB
CHUNK_SIZE = 32 # 32 bytes

class HandlerBase(ABC):
    HANDLER_NAME: str = None
    
    def __init__(self, *args, **kwargs) -> None:
        self.reverse: bool = kwargs["reverse"]
        super().__init__()
    
    @abstractmethod
    def handle(self, chunk: bytes) -> bytes:
        raise NotImplementedError

class BitReverseHandler(HandlerBase):
    HANDLER_NAME: str = "rev"
    
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
    
    def handle(self, chunk: bytes) -> bytes:
        chunk_length = len(chunk)
        uint = int.from_bytes(chunk, byteorder="big", signed=False)
        uint: int = 2**(chunk_length*8)-1 - uint
        return uint.to_bytes(chunk_length, byteorder="big", signed=False)

class SHA256PassphraseHandler(HandlerBase):
    HANDLER_NAME: str = "key256"
    
    def __init__(self, *args, **kwargs) -> None:
        if key is None:
            raise KeyError("Please specified a key, not None.")
        self.rotate_key: bytes = sha256(key.encode()).digest()
        super().__init__(*args, **kwargs)
    
    def handle(self, chunk: bytes) -> bytes:
        chunk_length = len(chunk)
        assert chunk_length <= 32 # using 256 bit rotate key
        uint = int.from_bytes(chunk, byteorder="big", signed=False)
        uint: int = uint ^ (
            int.from_bytes(
                self.rotate_key[:chunk_length], byteorder="big", signed=False
            )
        )
        new_chunk: bytes = uint.to_bytes(chunk_length, byteorder="big", signed=False)
        # rotate after handler each chunk
        original_text = chunk if not self.reverse else new_chunk
        to_rotate = self.rotate_key + original_text # (key + text) to rotate
        self.rotate_key: bytes = sha256(to_rotate).digest()
        
        return new_chunk

MODE_HANDLER_MAP: Dict[str, HandlerBase] = {
    BitReverseHandler.HANDLER_NAME: BitReverseHandler,
    SHA256PassphraseHandler.HANDLER_NAME: SHA256PassphraseHandler,
}

parser = ArgumentParser(
    prog="superxor",
    description="Super XOR program help you tweak with your files"
)
parser.add_argument(
    "input",
    action="store",
)
parser.add_argument(
    "-o",
    "--output",
    action="store",
    required=False,
)
parser.add_argument(
    "--to",
    action="store",
    required=False,
)
parser.add_argument(
    "-m",
    "--mode",
    action="store",
    required=False,
    default="rev", # BitReverseHandler
)
parser.add_argument(
    "-r",
    "--reverse",
    action="store_true",
    required=False,
)
parser.add_argument(
    "-k",
    "--key",
    action="store",
    required=False,
)

args: dict = vars(parser.parse_args())

input_location: str = args["input"].removesuffix(os.sep)
output_location: str = args.get("output", None)
to_dictionary: str = args.get("to", None)
mode: str = args["mode"]
reverse: bool = args["reverse"]
key: str = args.get("key", None)

if output_location and to_dictionary:
    raise NameError("Cannot specified both output location and to dictionary.")
if not output_location and not to_dictionary:
    raise NameError("You must specified output_location or to_dictionary")

if to_dictionary:
    to_dictionary = to_dictionary.removesuffix(os.sep)
    if not os.path.isdir(input_location):
        raise FileNotFoundError(
            f"to_dictionary specified, but {input_location} is not a dictionary."
        )
    if input_location in (".", ".."):
        raise FileNotFoundError("Invalid input_location(cannot be this dir/parent dir)")
    if not os.path.exists(to_dictionary):
        os.mkdir(to_dictionary)
elif output_location:
    if not os.path.isfile(input_location):
        raise FileNotFoundError(f"file `{input_location}` not exists.")

if mode not in MODE_HANDLER_MAP:
    raise NameError(f"Cannot found handler for `{mode}` mode.")

def handle_file(handler: HandlerBase, input: str, output: str):
    with open(input, "rb") as _f, open(output, "wb") as _output:
        logging.info(f"Open {input} for reading.")
        while True:
            _blk = _f.read(BLOCK_SIZE)
            if not _blk:
                break
            
            # output when reach every MB
            if _f.tell() % (1024 * 1024) == 0:
                logger.info(f"Readed {_f.tell() // (1024*1024)} MB for now.")
            
            new_blk = b""
            for idx in range(0, len(_blk), CHUNK_SIZE):
                chunk = _blk[idx:idx+CHUNK_SIZE]
                new_blk += handler.handle(chunk)
            _output.write(new_blk)

if output_location:
    handler: HandlerBase = MODE_HANDLER_MAP[mode](reverse=reverse, key=key)
    handle_file(handler=handler, input=input_location, output=output_location)
else:
    search = [input_location]
    
    while search:
        search_obj = search.pop()
        for entry in os.scandir(search_obj):
            rpath = os.path.join(
                *entry.path.split(os.sep)[input_location.count(os.sep)+1:]
            )
            if entry.is_file():
                handler: HandlerBase = MODE_HANDLER_MAP[mode](reverse=reverse, key=key)
                handle_file(
                    handler=handler,
                    input=os.path.join(input_location, rpath),
                    output=os.path.join(to_dictionary, rpath)
                )
                continue
            target_dictionary = os.path.join(to_dictionary, rpath)
            if not os.path.isdir(target_dictionary):
                os.mkdir(target_dictionary)
                logging.info(f"create dictionary: {target_dictionary}")

            search.append(entry.path)

logger.info(f"All done!")