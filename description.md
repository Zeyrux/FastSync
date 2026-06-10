# jetstream - A High-Performance File Transfer Utility

## Features

## Architecture ideas

### Pipeline Stages Client

- Directory Scanning -> Files
- File Reading -> SendableBuffer
- optional: Compression -> Sendable Buffer
- Send Data

### Pipeline Stages Server

- Receive Data -> Sendable Buffer
- optional: Decompress -> Files
- File Writing

### Passing Data between Steps

- use Queue

##
