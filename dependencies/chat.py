import os
import sys
import discord
import asyncio
import logging

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
        "FAIL"
        sys.exit()

    client.run('username', 'password')
