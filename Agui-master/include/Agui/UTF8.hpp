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

#ifndef AGUI_UTF8_HPP
#define AGUI_UTF8_HPP
#include "Agui/Platform.hpp"
#include <stdlib.h>
#include <string>
namespace agui
{
	/**
     * Class with useful UTF8 methods.
	 *
	 * Most methods are template so this class is not DLL exported. It is inline.
     * @author Joshua Larouche
     * @since 0.1.0
     */
	class UTF8 {
	public:
	/**
     * Moves the iterator to next unicode character in the string.
	 * @return Number of bytes skipped.
     * @since 0.1.0
     */
		template<typename _Iterator1, typename _Iterator2>
		inline size_t bringToNextUnichar(_Iterator1& it,
			const _Iterator2& last) const {
				if(it == last) return 0;
				unsigned char c;
				size_t res = 1;
				for(++it; last != it; ++it, ++res) {
					c = *it;
					if(!(c&0x80) || ((c&0xC0) == 0xC0)) break;
				}

				return res;
		}


	/**
     * Moves the iterator to next unicode character in the string.
	 * @return Number of bytes skipped.
     * @since 0.1.0
     */
		inline size_t bringToNextUnichar(size_t &index,
			const std::string &str) const {
				if(index >= str.length() ) return 0;
				unsigned char c;
				size_t res = 1;
				for(++index; index < str.length(); ++index, ++res) {
					c = str[index];
					if(!(c&0x80) || ((c&0xC0) == 0xC0)) break;
				}

				return res;
		}
	
	/**
     * Moves the iterator to previous unicode character in the string.
	 * @return Number of bytes skipped.
     * @since 0.1.0
     */
		template<typename _Iterator1, typename _Iterator2>
		inline size_t bringToPrevUnichar(_Iterator1& it,
			const _Iterator2& last) const {
				if(it == last) return 0;
				unsigned char c;
				size_t res = 1;
				for(--it; last != it; --it, ++res) {
					c = *it;
					if(!(c&0x80) || ((c&0xC0) == 0xC0)) break;
				}

				return res;
		}


	/**
     * Moves the iterator forward by count UTF8 characters.
	 * @return Number of bytes skipped.
     * @since 0.1.0
     */
		template<typename _Iterator>
		inline size_t _multIncUtf8StringIterator(_Iterator& it, 
			const _Iterator& last, size_t count) const {
				size_t res = 0;
				for(size_t i = 0; i < count; i++) {
					if(it == last) break;
					res += bringToNextUnichar(it, last);
				}

				return res;
		}

	/**
     * Moves the iterator to the first UTF8 character.
	 * @return Number of bytes skipped.
     * @since 0.1.0
     */
		template<typename _Iterator1, typename _Iterator2>
		inline size_t _decUtf8StringIterator(_Iterator1& it,
			const _Iterator2& first) const {
				if(it == first) return 0;
				size_t res = 1;
				unsigned char c;
				--it;
				for(; first != it; --it, ++res) {
					c = *it;
					if(!(c&0x80) || ((c&0xC0) == 0xC0)) break;
				}

				return res;
		}
	/**
     * Moves the iterator forward by count UTF8 characters.
	 * @return Iterator.
     * @since 0.1.0
     */
		template<typename _Iterator>
		inline _Iterator _getMultIncUtf8StringIterator(_Iterator it,
			const _Iterator& last, size_t count) const {
				_multIncUtf8StringIterator(it, last, count);
				return it;
		}

	/**
     * Moves the iterator to the specified position.
	 * @return Iterator.
     * @since 0.1.0
     */
		inline std::string::const_iterator _positionToIterator
			(const std::string& str, size_t pos) const {
				std::string::const_iterator res = str.begin();
				_multIncUtf8StringIterator(res, str.end(), pos);
				return res;
		}

			/**
     * Moves the iterator to the specified position.
	 * @return Iterator.
     * @since 0.1.0
     */
		inline std::string::iterator _positionToIterator(std::string& str,
			size_t pos) const {
				std::string::iterator res = str.begin();
				_multIncUtf8StringIterator(res, str.end(), pos);
				return res;
		}

	/**
	 * @return The number of UTF8 characters in this string.
     * @since 0.1.0
     */
		inline size_t length(const std::string& str) const  {
			size_t res = 0;
			std::string::const_iterator it = str.begin();
			for(; it != str.end(); bringToNextUnichar(it, str.end()))
				res++;

			return res;
		}

	/**
	 * @return The UTF8 sub string. All values are in UTF8 characters.
	 *
	 * The returned substring is from start to start + n UTF8 characters.
     * @since 0.1.0
     */
		inline std::string subStr(const std::string& str, size_t start,
			size_t n = (size_t)-1) const {
				if (n == (size_t)-1)
					return std::string(_positionToIterator(str, start), str.end());
				else
					return std::string(
					_positionToIterator(str, start),
					_positionToIterator(str, start + n));
		}
	/**
	 * Erases just like a normal string but values are in UTF8 characters, not bytes.
     * @since 0.1.0
     */
		inline void erase(std::string& str, size_t start,
			size_t n = (size_t)-1) const {
				std::string::iterator it = _positionToIterator(str, start);
				str.erase(it, _getMultIncUtf8StringIterator(it, str.end(), n));	
		}
	/**
	 * Inserts just like a normal string but values are in UTF8 characters, not bytes.
     * @since 0.1.0
     */
		inline void insert(std::string& str, size_t start,
			const std::string& s) const {
				str.insert(_positionToIterator(str, start), s.begin(), s.end());
		}

	/**
	 * @return The number of bytes the UTF32 encoded character 'c' will occupy in UTF8 form.
     * @since 0.1.0
     */
		inline size_t getUnicharLength(int c) const
		{

			size_t uc = c;

			if (uc <= 0x7f)
				return 1;
			if (uc <= 0x7ff)
				return 2;
			if (uc <= 0xffff)
				return 3;
			if (uc <= 0x10ffff)
				return 4;
			/* The rest are illegal. */
			return 0;
		}
	/**
	 * @return The number of bytes written to outputChars.
	 *
	 * ouputChars should have enough room for the number of bytes + NULL.
	 * Usually 5 bytes is enough.
     * @since 0.1.0
     */
		inline size_t encodeUtf8(char outputChars[], int inputUnichar) const 
		{
			size_t uc = inputUnichar;

			if (uc <= 0x7f) {
				outputChars[0] = static_cast<char>(uc);
				return 1;
			}

			if (uc <= 0x7ff) {
				outputChars[0] = 0xC0 | ((uc >> 6) & 0x1F);
				outputChars[1] = 0x80 |  (uc       & 0x3F);
				return 2;
			}

			if (uc <= 0xffff) {
				outputChars[0] = 0xE0 | ((uc >> 12) & 0x0F);
				outputChars[1] = 0x80 | ((uc >>  6) & 0x3F);
				outputChars[2] = 0x80 |  (uc        & 0x3F);
				return 3;
			}

			if (uc <= 0x10ffff) {
				outputChars[0] = 0xF0 | ((uc >> 18) & 0x07);
				outputChars[1] = 0x80 | ((uc >> 12) & 0x3F);
				outputChars[2] = 0x80 | ((uc >>  6) & 0x3F);
				outputChars[3] = 0x80 |  (uc        & 0x3F);
				return 4;
			}

			/* Otherwise is illegal. */
			return 0;
		}

	};
}
#endif

