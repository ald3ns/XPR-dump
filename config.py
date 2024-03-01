import argparse
import binaryninja


def initialize_data(byte_string):
    return [ord(char) for char in byte_string]


def decrypt(data, key):
    decrypted = [
        chr(byte ^ (key >> ((i * 8) & 0x38)) & 0xFF) for i, byte in enumerate(data)
    ]
    print("".join(decrypted))

    return data


def get_string_calls(curr, bv):
    # no mod_init_func was found so we just dip
    if len(curr) == 0:
        return

    body = curr[0]

    data_buffer = []  # store the encrypted strings from the bufs
    key = ""  # extract the key, we're gonna end up setting this a few times but w/e

    for bb in body.hlil:
        data = ""
        # I'm relatively sure we don't need this but I'm too lazy to check
        for inst in bb:
            # If the token is a call, and the destination is a function
            # that does memory or string stuff, we'll grab those params
            if isinstance(inst, binaryninja.highlevelil.HighLevelILCall):
                match str(inst.dest):
                    # We have reached an exitpoint so we can dump the buffer
                    case "___cxa_atexit":
                        if len(data) > 0:
                            data_buffer.append(data)
                            data = ""
                        else:
                            # Sometimes stuff gets weird!
                            data_buffer.append("what da heck")
                            data = ""
                    case "_memcpy":
                        data_addr = inst.params[1]
                        data_len = inst.params[2]
                        data_buffer.append(
                            bv.read(data_addr.constant, data_len.constant).decode(
                                "utf-8"
                            )
                        )
                    case "__builtin_memcpy":
                        dest, src, n = inst.params
                        data += str(src.constant_data.data)
                    case "__builtin_strncpy":
                        dest, src, n = inst.params
                        data += str(src.constant_data.data)
                    case _:
                        pass

            # This is really icky but basically we yoink the key from the
            # text of an identified dowhile loop. Sometimes it doesn't work, so we check
            # each iteration just incase the first one is messed up.
            elif isinstance(inst, binaryninja.highlevelil.HighLevelILDoWhile):
                key_buf = [i for i in inst.body]
                try:
                    key = (
                        str(key_buf[0])
                        .split("^")[1]
                        .split("u>>")[0]
                        .strip()
                        .replace("(", "")
                    )
                except:
                    key = ""
            else:
                pass

    return data_buffer, key


def main():
    parser = argparse.ArgumentParser(description="Script Description.")
    parser.add_argument("file_path", help="Path to the binary file to analyze.")
    parser.add_argument("--key", default=None, help="Optional key for decryption.")
    args = parser.parse_args()

    # This is hella useful tidbit for grabbing your preferred bit of a FAT binary
    bv = binaryninja.load(
        args.file_path, options={"files.universal.architecturePreference": ["x86_64"]}
    )

    # DUBIOUS for sure
    curr = bv.get_functions_by_name("mod_init_func_0")

    data_buffer, key_identified = get_string_calls(curr, bv)
    print(f"[+] KEY IDENTIFIED: {key_identified}")
    # print(f"[+] DATA BUFFER: {data_buffer}")
    if args.key is not None:
        key = args.key

    for i in data_buffer:
        decrypt(initialize_data(i), int(key, 16))


if __name__ == "__main__":
    main()
