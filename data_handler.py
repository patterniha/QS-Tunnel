import asyncio
import sys


class DataHandler:
    def __init__(self, offsets_size: int, assemble_time: float) -> None:
        self.offsets_size = offsets_size
        self.assemble_time = assemble_time
        self.lock = asyncio.Lock()
        self.mpp_list: list = [None] * offsets_size
        self.active_keys_queue = asyncio.Queue(maxsize=offsets_size)
        self.cleaner_task = asyncio.create_task(self.cleanup())

    async def cleanup(self) -> None:
        try:
            loop = asyncio.get_running_loop()
            await asyncio.sleep(self.assemble_time)
            while True:
                key: int
                add_time: float
                key, add_time = await self.active_keys_queue.get()
                alive_time = self.assemble_time - (loop.time() - add_time)
                if alive_time <= 0:
                    async with self.lock:
                        self.mpp_list[key] = None
                else:
                    await asyncio.sleep(alive_time)
                    async with self.lock:
                        self.mpp_list[key] = None

        except Exception as e:
            print(e)
            sys.exit("cleanup error!")

    async def new_data_event(self, key: int, fragment_part: int, last_fragment: bool, data: bytes) -> bytes:
        loop = asyncio.get_running_loop()
        async with self.lock:
            mpp = self.mpp_list[key]
            if mpp is None:
                rec_nums = 1
                biggest_index_plus_one = fragment_part + 1
                seen_last_fragment = last_fragment
                if seen_last_fragment and rec_nums == biggest_index_plus_one:
                    self.mpp_list[key] = True
                    await self.active_keys_queue.put((key, loop.time()))
                    return data

                mpp = [None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                       None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                       None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                       None, None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
                       rec_nums, biggest_index_plus_one, seen_last_fragment]
                mpp[fragment_part] = data
                self.mpp_list[key] = mpp
                await self.active_keys_queue.put((key, loop.time()))
                return b""

            if (mpp is True) or (mpp is False):
                return b""
            if mpp[fragment_part] is not None:
                return b""

            mpp[fragment_part] = data
            rec_nums = mpp[-3] + 1
            fp_po = fragment_part + 1
            p_biggest = mpp[-2]
            if fp_po > p_biggest:
                biggest_updated = True
                biggest_index_plus_one = fp_po
            else:
                biggest_index_plus_one = p_biggest
                biggest_updated = False
            p_seen_last_frag = mpp[-1]
            if (last_fragment and p_seen_last_frag) or (biggest_updated and p_seen_last_frag) or (
                    (not biggest_updated) and last_fragment):
                self.mpp_list[key] = False
                return b""
            seen_last_fragment = last_fragment or p_seen_last_frag

            if seen_last_fragment and rec_nums == biggest_index_plus_one:
                self.mpp_list[key] = True
                return b"".join(mpp[:rec_nums])

            mpp[-3] = rec_nums
            if last_fragment:
                mpp[-1] = True
            if biggest_updated:
                mpp[-2] = biggest_index_plus_one
            return b""
