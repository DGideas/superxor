"""
superXOR by DGideas
(c) 2023 dgideas@outlook.com
published under WTFPL, do anything you want!
"""
from typing import Dict
from abc import ABC, abstractmethod
from argparse import ArgumentParser

BLOCK_SIZE = 64 * 1024
CHUNK_SIZE = 32

class HandlerBase(ABC):
    HANDLER_NAME: str = None
    
    def __init__(self, *args, **kwargs) -> None:
        self.reverse: bool = kwargs.get("reverse", False)
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

MODE_HANDLER_MAP: Dict[str, HandlerBase] = {
    BitReverseHandler.HANDLER_NAME: BitReverseHandler,
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

args: dict = vars(parser.parse_args())

input_location: str = args["input"]
output_location: str = args.get("output", input_location)
mode: str = args["mode"]
reverse: bool = args["reverse"]

if mode not in MODE_HANDLER_MAP:
    raise NameError(f"Cannot found handler for `{mode}` mode.")

handler: HandlerBase = MODE_HANDLER_MAP[mode](reverse=reverse)

with open(input_location, "rb") as _f, open(output_location, "wb") as _output:
    while True:
        _blk = _f.read(BLOCK_SIZE)
        if not _blk:
            break
        new_blk = b""
        for idx in range(0, len(_blk), CHUNK_SIZE):
            chunk = _blk[idx:idx+CHUNK_SIZE]
            new_blk += handler.handle(chunk)
        _output.write(new_blk)
