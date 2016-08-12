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

#ifndef AGUI_BASE_TYPES_HPP
#define AGUI_BASE_TYPES_HPP

#include <stdlib.h> 
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>

//C runtime
#include <cmath> 
#include <ctime>
#include "Agui/Platform.hpp"
#include "Agui/Enumerations.hpp"
#include "Agui/Point.hpp"
#include "Agui/Dimension.hpp"
#include "Agui/Rectangle.hpp"
#include "Agui/UTF8.hpp"
#include "Agui/Font.hpp"
#include "Agui/Image.hpp"
#include "Agui/ActionEvent.hpp"
#include "Agui/ResizableText.hpp"

namespace agui {

	/**
     * Class used to throw exceptions.
	 *
	 * Catch these types of exceptions in your main loop.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC Exception{
		std::string message;
	public:
	/**
     * Constructs with error message.
     * @since 0.1.0
     */
		Exception(std::string message)
		{
			this->message = message;
		}
	/**
     * @return The error message.
     * @since 0.1.0
     */
		std::string getMessage() const
		{
			return message;
		}

	/**
     * Default destructor.
     * @since 0.1.0
     */
		virtual ~Exception()
		{

		}

	};


	/**
     * Compares two strings while keeping in mind that 110 > 12.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class AGUI_CORE_DECLSPEC NumericStringCompare
	{
	public:
	/**
     * @return True if a < b.
     * @since 0.1.0
     */
		virtual bool compare(const std::string& a, const std::string& b);
		virtual ~NumericStringCompare();
	};

}
#endif







