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

#include "Agui/Transform.hpp"
#include <cmath>
namespace agui 
{
	void Transform::identity()
	{
		m[0][0] = 1;
		m[0][1] = 0;
		m[0][2] = 0;
		m[0][3] = 0;

		m[1][0] = 0;
		m[1][1] = 1;
		m[1][2] = 0;
		m[1][3] = 0;

		m[2][0] = 0;
		m[2][1] = 0;
		m[2][2] = 1;
		m[2][3] = 0;

		m[3][0] = 0;
		m[3][1] = 0;
		m[3][2] = 0;
		m[3][3] = 1;
	}

	Transform::Transform()
	{
		identity();
	}

	Transform::Transform( float matrix[4][4] )
	{
		for(int i = 0; i < 4; ++i)
		{
			for(int j = 0; j < 4; ++j)
			{
				m[i][j] = matrix[i][j];
			}
		}
	}

	void Transform::invert()
	{
		float det, t;

		det =  m[0][0] *  m[1][1] -  m[1][0] *  m[0][1];

		t =  m[3][0];
		m[3][0] = ( m[1][0] *  m[3][1] - t *  m[1][1]) / det;
		m[3][1] = (t *  m[0][1] -  m[0][0] *  m[3][1]) / det;

		t =  m[0][0];
		m[0][0] =  m[1][1] / det;
		m[1][1] = t / det;

		m[0][1] = - m[0][1] / det;
		m[1][0] = - m[1][0] / det;
	}

	void Transform::translate( float x, float y )
	{
		m[3][0] += x;
		m[3][1] += y;
	}

	void Transform::translate( float x, float y, float z )
	{
		m[3][0] += x;
		m[3][1] += y;
		m[3][2] += z;
	}

	void Transform::rotate( float theta )
	{
		float c, s;
		float t;

		c = cosf(theta);
		s = sinf(theta);

		t = m[0][0];
		m[0][0] = t * c - m[0][1] * s;
		m[0][1] = t * s + m[0][1] * c;

		t = m[1][0];
		m[1][0] = t * c - m[1][1] * s;
		m[1][1] = t * s + m[1][1] * c;

		t = m[3][0];
		m[3][0] = t * c - m[3][1] * s;
		m[3][1] = t * s + m[3][1] * c;
	}

	void Transform::rotate( float x, float y, float z, float angle )
	{
		float s = sin(angle);
		float c = cos(angle);
		float cc = 1 - c;
		Transform tmp;

		tmp.m[0][0] = (cc * x * x) + c;
		tmp.m[0][1] = (cc * x * y) + (z * s);
		tmp.m[0][2] = (cc * x * z) - (y * s);
		tmp.m[0][3] = 0;

		tmp.m[1][0] = (cc * x * y) - (z * s);
		tmp.m[1][1] = (cc * y * y) + c;
		tmp.m[1][2] = (cc * z * y) + (x * s);
		tmp.m[1][3] = 0;

		tmp.m[2][0] = (cc * x * z) + (y * s);
		tmp.m[2][1] = (cc * y * z) - (x * s);
		tmp.m[2][2] = (cc * z * z) + c;
		tmp.m[2][3] = 0;

		tmp.m[3][0] = 0;
		tmp.m[3][1] = 0;
		tmp.m[3][2] = 0;
		tmp.m[3][3] = 1;

		compose(tmp);
	}

	void Transform::compose( const Transform& other )
	{
		#define E(x, y)                        \
			(other.m[0][y] * m[x][0] +  \
			other.m[1][y] * m[x][1] +  \
			other.m[2][y] * m[x][2] +  \
			other.m[3][y] * m[x][3])   \

			 
				float tarr[4][4] = {
					{ E(0, 0), E(0, 1), E(0, 2), E(0, 3) },
					{ E(1, 0), E(1, 1), E(1, 2), E(1, 3) },
					{ E(2, 0), E(2, 1), E(2, 2), E(2, 3) },
					{ E(3, 0), E(3, 1), E(3, 2), E(3, 3) }
				};

				Transform tmp = Transform(tarr);
				*this = tmp;

		#undef E
	}

	void Transform::scale( float sx, float sy )
	{
		m[0][0] *= sx;
		m[0][1] *= sy;

		m[1][0] *= sx;
		m[1][1] *= sy;

		m[3][0] *= sx;
		m[3][1] *= sy;
	}

	void Transform::scale( float sx, float sy, float sz )
	{
		m[0][0] *= sx;
		m[0][1] *= sy;
		m[0][2] *= sz;

		m[1][0] *= sx;
		m[1][1] *= sy;
		m[1][2] *= sz;

		m[2][0] *= sx;
		m[2][1] *= sy;
		m[2][2] *= sz;

		m[3][0] *= sx;
		m[3][1] *= sy;
		m[3][2] *= sz;
	}

	void Transform::transformPoint( float* x, float* y )
	{
		float t;
		t = *x;

		*x = t * m[0][0] + *y * m[1][0] + m[3][0];
		*y = t * m[0][1] + *y * m[1][1] + m[3][1];
	}


}
