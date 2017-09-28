import os
import sys
import discord
import asyncio
import logging

import config as cfg

client = discord.Client()

@client.event
async def on_ready():
    for server in client.servers:
        for channel in server.channels:
            await client.send_message(channel, msg)
            try:
                sys.exit(0)
            except SystemExit:
                os._exit(0)

if __name__ == "__main__":
    global msg
    msg = ""
    if len(sys.argv) > 1:
        msg = sys.argv[1]
    else:
        sys.exit()

    client.run(cfg.discordname, cfg.discordpw)
