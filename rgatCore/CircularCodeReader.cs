/*
 * 
 * This is for moving from capstone to Iced
 * The APIs are very different so its going to be more work than I thought and will have to wait for another release
 * 
 */

/*
using System;

namespace rgat {

	public class RingDisassembler : IDisposable
    {
		CircularCodeReader buffer; 
		Iced.Intel.Decoder disassembler;
		Iced.Intel.InstructionInfoFactory instrInfoFactory = new Iced.Intel.InstructionInfoFactory();

		public RingDisassembler(int bufSize, int bitWidth)
        {
			buffer = new CircularCodeReader(bufSize);
			disassembler = Iced.Intel.Decoder.Create(bitWidth, buffer, Iced.Intel.DecoderOptions.MPX);
		}

		public void AddBytes(byte[] bytes) => buffer.AddBytes(bytes);
		public void Disassemble(out Iced.Intel.Instruction instruction, out Iced.Intel.InstructionInfo info)
		{
			disassembler.Decode(out instruction);
			info = instrInfoFactory.GetInfo(instruction);
		}
		public void Dispose() { }
    }

	/// <summary>
	/// A <see cref="CodeReader"/> that reads data from a byte array
	/// </summary>
	public sealed class CircularCodeReader : Iced.Intel.CodeReader {
		RingByteBuffer.SequentialRingBuffer buffer;

		/// <summary>
		/// Creates a CodeReader with a circular buffer
		/// </summary>
		/// <param name="data">Data</param>
		public CircularCodeReader(int size)
		{
			buffer = new RingByteBuffer.SequentialRingBuffer(size);
		}

		/// <summary>
		/// Reads the next byte
		/// </summary>
		/// <returns></returns>
		public override int ReadByte() {
			if (buffer.CurrentLength == 0)
				return -1;
			return buffer.Take();
		}


		/// <summary>
		/// Adds more bytes
		/// </summary>
		/// <returns></returns>
		public void AddBytes(byte[] bytes)
		{
			if (buffer.Spare < bytes.Length)
				throw new OutOfMemoryException("Not enough space in the ringbuffer"); //no need for this, just block
			buffer.Put(bytes);
		}

		public bool HasData => buffer.CurrentLength > 0;
	}
}
*/