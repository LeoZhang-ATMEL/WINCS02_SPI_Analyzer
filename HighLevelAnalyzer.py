
# Copyright (c) 2023 iAchieved.it LLC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, ChoicesSetting

# See 23A512/23LC512 datasheet, INSTRUCTION SET
WRITE_INS = b'\x02'
READ_INS  = b'\x03'
RMDR_INS  = b'\x05'
WRMR_INS  = b'\x01'

# Operation Modes of the 23A512/23LC512
BYTE_MODE       = 0x00
PAGE_MODE       = 0x02
SEQUENTIAL_MODE = 0x01
RESERVED        = 0x03

# Analyzer states for Byte mode
START      = 0
GET_CMD    = 1
GET_INS    = 1
GET_ADDR_H = 2
GET_ADDR_L = 3
GET_DATA   = 4

# High level analyzers must subclass the HighLevelAnalyzer class.
class HLA_WINCS02_SPI(HighLevelAnalyzer):

  mode_setting = ChoicesSetting(choices=('Sequential', 'Byte', 'Page'))

  result_types = {
    'Header': {
      'format': 'Header'
    },
    'Instruction': {
      'format': '{{data.instruction}}'
    },
    'Address': {
      'format':  'Address {{data.address}}'
    },
    'Data': {
      'format': 'Data:  {{data.data}}'
    },
    'Mode': {
      'format': '{{data.mode}} Mode'
    }
  }

  def __init__(self):
    '''
    Initialize HLA.
    '''

    state = START

  def instruction_str(self, instruction):
    if instruction == WRITE_INS:
      return 'Write'
    elif instruction == READ_INS:
      return 'Read'
    elif instruction == WRMR_INS:
      return 'Write Mode Register'
    elif instruction == RMDR_INS:
      return 'Read Mode Register'
    else:
      return 'Unknown'

  # Decodes the mode register value, see
  # 2.5 Read Mode Register Instruction of datasheet
  def decode_mode(self, mode_register):
    # Mode value is in Bits 7 and 6
    mode = (mode_register & 0xc0) >> 6
    return mode

  def mode_str(self, mode):
    if mode == BYTE_MODE:
      return 'Byte'
    elif mode == PAGE_MODE:
      return 'Page'
    elif mode == SEQUENTIAL_MODE:
      return 'Sequential'

  def decode(self, frame: AnalyzerFrame):
    # SPI frame types are: enable, result, and disable
    # enable
    # result
    # disable

    # A frame type of 'enable' triggers our state machine
    if frame.type == 'enable':
      self.state = START
    elif frame.type == 'result':
      if self.state == START:

        self.instruction = frame.data['mosi'] # Our instruction will be on the MOSI line
        self.address     = None               # Prepare to receive address
        self.data        = b''                # Prepare to receive data

        self.state = GET_CMD           # Next byte will be CMD

        return AnalyzerFrame('Header', frame.start_time, frame.end_time, {
          'header': 'Head'
        })

    elif frame.type == 'disable':

      if self.state == GET_DATA:
        # Return the data frame itself
        return AnalyzerFrame('Data',
          self.data_frame_start,
          self.data_frame_end, {
          'data': self.data
        })
      else:
        # This isn't a valid state
        pass