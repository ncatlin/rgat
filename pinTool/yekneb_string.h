#pragma once

#include <string>
#include <vector>

//https://yekneb.com/2018/11/09/cross-platform-conversion-between-string-and-wstring/
namespace yekneb
{
	namespace detail
	{
		namespace string_cast
		{

			inline std::wstring s2w(const std::string& s, const std::locale& loc)
			{
				typedef std::ctype<wchar_t> wchar_facet;
				std::wstring return_value;
				if (s.empty())
				{
					return L"";
				}
				if (std::has_facet<wchar_facet>(loc))
				{
					std::vector<wchar_t> to(s.size() + 2, 0);
					std::vector<wchar_t>::pointer toPtr = &to[0];
					const wchar_facet& facet = std::use_facet<wchar_facet>(loc);
					if (facet.widen(s.c_str(), s.c_str() + s.size(), toPtr) != 0)
					{
						return_value = &to[0];
					}
				}
				return return_value;
			}

		}
	}


	template<typename Target, typename Source>
	inline Target string_cast(const Source& source)
	{
		return source;
	}

	template<>
	inline std::wstring string_cast(const std::string& source)
	{
		std::locale loc;
		return ::yekneb::detail::string_cast::s2w(source, loc);
	}
}