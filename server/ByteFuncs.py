# Given an array insert to the end the number as nB representation
def push_as_n_bytes(arr: bytes, number, num_bytes: int) -> None:
    if isinstance(number, int):
        n = num_bytes - 1
        while n >= 0:
            arr.append((number >> (n * 8)) & 0xFF)
            n -= 1
    else:
        for var in number:
            arr.append(var)


def unpad(data: bytes) -> bytes:
    padding_len = data[-1]  # The last value is the padding length
    return data[:-padding_len]
