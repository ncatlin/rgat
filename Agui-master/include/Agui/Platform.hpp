/*   _____                           
 * /\  _  \                     __    
 * \ \ \_\ \      __    __  __ /\_\   
 *  \ \  __ \   /'_ `\ /\ \/\ \\/\ \  
 *   \ \ \/\ \ /\ \_\ \\ \ \_\ \\ \ \ 
 *    \ \_\ \_\\ \____ \\ \____/ \ \_\
 *     \/_/\/_/ \/____\ \\/___/   \/_/
 *                /\____/             
 *                \_/__/              
 *
 * Copyright (c) 2011 Joshua Larouche
 * 
 *
 * License: (BSD)
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of Agui nor the names of its contributors may
 *    be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#if defined (__MINGW32__) && defined(AGUI_BUILD)
#define AGUI_CORE_DECLSPEC __declspec(dllexport)

#elif defined (__MINGW32__) && defined(AGUI_BACKEND_BUILD)
#define AGUI_BACKEND_DECLSPEC __declspec(dllexport)
#define AGUI_CORE_DECLSPEC __declspec(dllimport)

#elif defined (__MINGW32__) && defined(AGUI_DLL_IMPORT)
#define AGUI_CORE_DECLSPEC __declspec(dllimport)
#define AGUI_BACKEND_DECLSPEC __declspec(dllimport)

#elif defined(_MSC_VER) && defined(AGUI_BUILD)
#define AGUI_CORE_DECLSPEC _declspec(dllexport)

#elif defined(_MSC_VER) && defined(AGUI_BACKEND_BUILD)
#define AGUI_CORE_DECLSPEC _declspec(dllimport)
#define AGUI_BACKEND_DECLSPEC _declspec(dllexport)

#endif

#ifndef AGUI_CORE_DECLSPEC
#define AGUI_CORE_DECLSPEC
#endif

#ifndef AGUI_BACKEND_DECLSPEC
#define AGUI_BACKEND_DECLSPEC
#endif

#if defined(_MSC_VER) && _MSC_VER < 1600
#define nullptr 0
#endif


