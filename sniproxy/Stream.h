#pragma once

#include "stdafx.h"
#include "SeekOrigin.h"

class Stream {
public:
    virtual bool                        CanSeek() noexcept = 0;
    virtual bool                        CanRead() noexcept = 0;
    virtual bool                        CanWrite() noexcept = 0;

public:
    virtual int                         GetPosition() noexcept = 0;
    virtual int                         GetLength() noexcept = 0;
    virtual bool                        Seek(int offset, SeekOrigin loc) noexcept = 0;
    virtual bool                        SetPosition(int position) noexcept = 0;
    virtual bool                        SetLength(int value) noexcept = 0;

public:
    virtual bool                        WriteByte(Byte value) noexcept = 0;
    virtual bool                        Write(const void* buffer, int offset, int count) noexcept = 0;

public:
    virtual int                         ReadByte() noexcept = 0;
    virtual int                         Read(const void* buffer, int offset, int count) noexcept = 0;

public:
    inline void                         Close() noexcept { this->Dispose(); }
    virtual void                        Dispose() noexcept = 0;
};
