//
// Copyright (c) 2007-2022  Made to Order Software Corp.  All Rights Reserved.
//
// https://snapwebsites.org/project/iplock
// contact@m2osw.com
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
#pragma once

/** \file
 * \brief Various definition of the iplock tool.
 *
 * The iplock is an object used to execute the command line instructions
 * as passed by the administrator.
 *
 * Depending on the command the system also loads configuration files
 * using the advgetopt library.
 */

// self
//
#include    "command.h"



namespace tool
{



class iplock
{
public:
                            iplock(int argc, char * argv[]);

    void                    run_command();

private:
    void                    set_command(command::pointer_t c);
    void                    make_root();

    command::pointer_t      f_command = command::pointer_t();
};



} // namespace tool
// vim: ts=4 sw=4 et
