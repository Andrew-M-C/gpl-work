/**********************************************************************************
	Copyright (C), 2002-2012, TP-LINK TECHNOLOGIES CO., LTD.

	File name:	tplink_4phase-motor.c
	Version:	0.0.1
	Author:		Andrew Chang (or Zhang Min, the same guy)
	
	Discription:
 			This is the driver to access GPIO based 4-phase motor. It provide simple
 		interface to initialize and control motor.
	
	History:
		2014-06-30: File created.
		2014-09-10: Add poll() support. Add motor stop detection.
		
 *********************************************************************************
	GPL declaration:
	
		This program is free software: you can redistribute it and/or modify it under the terms 
	of the GNU General Public License as published by the Free Software Foundation, either version 
	3 of the License, or any later version.

		This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
	without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR 
	PURPOSE.  See the GNU General Public License for more details. 

		You should have received a copy of the GNU General Public License along with this program. 
	If not, see <http://www.gnu.org/licenses/>.

		For any suggestions, problems and bug reports, please contact Andrew through either 
	Emails below:
	1. zhangmin@tp-link.com.cn		(company Email, as long as I am an employee of TP-LINK)
	2. laplacezhang@126.com			(personal Email)

 **********************************************************************************/

#include <linux/init.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/timer.h>
#include <linux/errno.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/poll.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
#include <linux/device.h>
#endif

#include "tplink_4phase_motor.h"

//#define	_TP_MOTOR_DEBUG
#define	_CFG_STOP_ALL_PORTS_WHEN_DELAYED	0
#define	_CFG_MOTOR_PIN_EXCITATION_HIGH		1
#define _CFG_MOTOR_PIN_LIMIT_HIGH			0




#ifdef	_TP_MOTOR_DEBUG
#define	_motor_print(fmt, args...)		printk("####"__FILE__", %d: "fmt, __LINE__, ##args)
#else
#define	_motor_print(fmt, args...)
#endif




MODULE_DESCRIPTION("TP-LINK 4-Phase Motor driver");
MODULE_AUTHOR("Andrew Chang <zhangmin@tp-link.com.cn, laplacezhang@126.com>");
MODULE_LICENSE("GPL");


/******** GPIO register definitions ********/
#define __GPIO_REGISTER_DEFINITIONS
#ifdef __GPIO_REGISTER_DEFINITIONS
#define	_REG_BASE				(0xb0000000)
#define	_REG_GPIO_BASE		(_REG_BASE | 0x0600)

#define	_REG_GPIO_23_00_DIR	(_REG_GPIO_BASE | 0x0024)
#define	_REG_GPIO_23_00_IN	(_REG_GPIO_BASE | 0x0020)
#define	_REG_GPIO_23_00_OUT	(_REG_GPIO_BASE | 0x0020)

#define	_REG_GPIO_39_24_DIR	(_REG_GPIO_BASE | 0x004C)
#define	_REG_GPIO_39_24_IN	(_REG_GPIO_BASE | 0x0048)
#define	_REG_GPIO_39_24_OUT	(_REG_GPIO_BASE | 0x0048)

#define	_REG_GPIO_71_40_DIR	(_REG_GPIO_BASE | 0x0074)
#define	_REG_GPIO_71_40_IN	(_REG_GPIO_BASE | 0x0070)
#define	_REG_GPIO_71_40_OUT	(_REG_GPIO_BASE | 0x0070)

#define	_REG_GPIO_72_72_DIR	(_REG_GPIO_BASE | 0x009C)
#define	_REG_GPIO_72_72_IN	(_REG_GPIO_BASE | 0x0098)
#define	_REG_GPIO_72_72_OUT	(_REG_GPIO_BASE | 0x0098)


#define	_REG_GPIO_PURPOSE		(_REG_BASE | 0x0000 | 0x0060)
#define	_MASK_GPIO_PURPOSE_SUTIF		(0x3 << 30)
#define	_MASK_GPIO_PURPOSE_OFF_SUTIF		(30)
#define	_MASK_GPIO_PURPOSE_WDT		(0x3 << 21)
#define	_MASK_GPIO_PURPOSE_OFF_WDT			(21)
#define	_MASK_GPIO_PURPOSE_PA		(0x1 << 20)
#define	_MASK_GPIO_PURPOSE_OFF_PA			(20)
#define _MASK_GPIO_PURPOSE_NAND_SD	(0x3 << 18)
#define _MASK_GPIO_PURPOSE_OFF_NAND_SD		(18)
#define _MASK_GPIO_PURPOSE_PERST		(0x3 << 16)
#define _MASK_GPIO_PURPOSE_OFF_PERST		(16)
#define _MASK_GPIO_PURPOSE_EPHY_LED	(0x1 << 15)
#define _MASK_GPIO_PURPOSE_OFF_EPHY_LED		(15)
#define _MASK_GPIO_PURPOSE_WLED		(0x1 << 13)
#define _MASK_GPIO_PURPOSE_OFF_WLED			(13)
#define _MASK_GPIO_PURPOSE_SPI_REFCLK0	(0x1 << 12)
#define _MASK_GPIO_PURPOSE_OFF_SPI_REFCLK0	(12)
#define _MASK_GPIO_PURPOSE_SPI		(0x1 << 11)
#define _MASK_GPIO_PURPOSE_OFF_SPI			(11)
#define _MASK_GPIO_PURPOSE_RGMII2	(0x1 << 10)
#define _MASK_GPIO_PURPOSE_OFF_RGMII2		(10)
#define _MASK_GPIO_PURPOSE_RGMII1	(0x1 << 9)
#define _MASK_GPIO_PURPOSE_OFF_RGMII1		(9)
#define _MASK_GPIO_PURPOSE_MDIO		(0x3 << 7)
#define _MASK_GPIO_PURPOSE_OFF_MDIO			(7)
#define _MASK_GPIO_PURPOSE_UARTL		(0x1 << 5)
#define _MASK_GPIO_PURPOSE_OFF_UARTL		(5)
#define _MASK_GPIO_PURPOSE_UARTF		(0x7 << 2)
#define _MASK_GPIO_PURPOSE_OFF_UARTF		(2)
#define _MASK_GPIO_PURPOSE_I2C		(0x1 << 0)
#define _MASK_GPIO_PURPOSE_OFF_I2C			(0)

#endif



/******** Global variables and register operations ********/
#define __GLOBAL_VARIABLES_AND_REG_OPS
#ifdef __GLOBAL_VARIABLES_AND_REG_OPS
static struct mutex _motorMutex;
static struct mutex _ioctlMutex;
#define	_LOCK()				mutex_lock(&_motorMutex);
#define	_UNLOCK()			mutex_unlock(&_motorMutex);


static signed long _motorSpeedDivCountDown[CFG_4_PHASE_MOTOR_COUNT];
static signed long _motorIfIsPositiveFound[CFG_4_PHASE_MOTOR_COUNT];
static signed long _motorIfIsNegativeFound[CFG_4_PHASE_MOTOR_COUNT];

static signed long _motorStepRequirement[CFG_4_PHASE_MOTOR_COUNT];

static TP_4PhaseMotorConfig_st _motorIfConf[CFG_4_PHASE_MOTOR_COUNT];
static TP_4PhaseMotorStatus_st _motorIfStatus[CFG_4_PHASE_MOTOR_COUNT];


#define	_REG_SET_BITS(reg, offset)		((*(volatile u32 *)(reg)) |= (1 << (offset)))
#define	_REG_CLR_BITS(reg, offset)		((*(volatile u32 *)(reg)) &= ~(1 << (offset)))

#define	_REG_GET_VAL(reg)			(*(volatile u32 *)(reg))
#define	_REG_SET_VAL(reg, val)	((*(volatile u32 *)(reg)) = (val))


#define	_NAME		"TPLINK_4Phase_motor"
#define	_DEV_NAME	"motor"
static int _tpMotorMajor = 225;

static BOOL _isTimerRunning = FALSE;
static struct timer_list _tpMotorTimer;

static DECLARE_WAIT_QUEUE_HEAD(_motorStopQueue);
static BOOL _isAnyMotorStopped = FALSE;


#if _CFG_MOTOR_PIN_EXCITATION_HIGH
#define	_GPIO_SET_PIN_IDLE(gpioNum)			_gpioSetPinLow(gpioNum)		/* idle, 0 */
#define	_GPIO_SET_PIN_XCTA(gpioNum)			_gpioSetPinHigh(gpioNum)		/* excitation, 1 */
#else
#define	_GPIO_SET_PIN_IDLE(gpioNum)			_gpioSetPinHigh(gpioNum)
#define	_GPIO_SET_PIN_XCTA(gpioNum)			_gpioSetPinLow(gpioNum)
#endif


#if _CFG_MOTOR_PIN_LIMIT_HIGH
#define _GPIO_REACH_LIMIT(gpioNum)			_gpioIsHigh(gpioNum)
#else
#define _GPIO_REACH_LIMIT(gpioNum)			(!_gpioIsHigh(gpioNum))
#endif


#endif



/******** GPIO operation functions ********/
#define __GPIO_OPERATION_FUNCTIONS
#ifdef __GPIO_OPERATION_FUNCTIONS

/*    reg: 		register address
 * 	  mask:		mask value such as 0x0380				(0000 0011 1000 0000)
 *    maskValue:value INCLUDING offset such as 0x0200	(0000 0010 0000 0000)
 */
void _gpioSetRegMaskValue(u32 reg, u32 mask, u32 maskValue)
{
	u32 regValue = _REG_GET_VAL(reg);

	regValue &=~mask;
	regValue |= maskValue;

	_REG_SET_VAL(reg, regValue);
}





u32 _gpioDirReg(unsigned long gpioNum)
{
	if (gpioNum > 72)
	{
		return 0;
	}
	else if (gpioNum >= 72)
	{
		return _REG_GPIO_72_72_DIR;
	}
	else if (gpioNum >= 40)
	{
		return _REG_GPIO_71_40_DIR;
	}
	else if (gpioNum >= 24)
	{
		return _REG_GPIO_39_24_DIR;
	}
	else
	{
		return _REG_GPIO_23_00_DIR;
	}
}


u32 _gpioOutValReg(unsigned long gpioNum)
{
	if (gpioNum > 72)
	{
		return 0;
	}
	else if (gpioNum >= 72)
	{
		return _REG_GPIO_72_72_OUT;
	}
	else if (gpioNum >= 40)
	{
		return _REG_GPIO_71_40_OUT;
	}
	else if (gpioNum >= 24)
	{
		return _REG_GPIO_39_24_OUT;
	}
	else
	{
		return _REG_GPIO_23_00_OUT;
	}
}


u32 _gpioInValReg(unsigned long gpioNum)
{
	if (gpioNum > 72)
	{
		return 0;
	}
	else if (gpioNum >= 72)
	{
		return _REG_GPIO_72_72_IN;
	}
	else if (gpioNum >= 40)
	{
		return _REG_GPIO_71_40_IN;
	}
	else if (gpioNum >= 24)
	{
		return _REG_GPIO_39_24_IN;
	}
	else
	{
		return _REG_GPIO_23_00_IN;
	}
}


u32 _gpioOffsetNum(unsigned long gpioNum)
{
	if (gpioNum > 72)
	{
		return 0;
	}
	else if (gpioNum >= 72)
	{
		return 0;
	}
	else if (gpioNum >= 40)
	{
		return gpioNum - 40;
	}
	else if (gpioNum >= 24)
	{
		return gpioNum - 24;
	}
	else
	{
		return gpioNum;
	}
}


static void _gpioSetPortAsGpioMode(int gpioNum)
{
	if (gpioNum > 72)
	{
		/* invalid GPIO number */
	}
	else if (gpioNum >= 72)
	{
		_gpioSetRegMaskValue(_REG_GPIO_PURPOSE, 
								_MASK_GPIO_PURPOSE_WLED, 
								1 << _MASK_GPIO_PURPOSE_OFF_WLED);
	}
	else if (gpioNum >= 60)
	{
		_gpioSetRegMaskValue(_REG_GPIO_PURPOSE, 
								_MASK_GPIO_PURPOSE_RGMII2, 
								1 << _MASK_GPIO_PURPOSE_OFF_RGMII2);
	}
	else if (gpioNum >= 45)
	{
		_gpioSetRegMaskValue(_REG_GPIO_PURPOSE, 
								_MASK_GPIO_PURPOSE_NAND_SD, 
								2 << _MASK_GPIO_PURPOSE_OFF_NAND_SD);
	}
	else if (gpioNum >= 40)
	{
		_gpioSetRegMaskValue(_REG_GPIO_PURPOSE, 
								_MASK_GPIO_PURPOSE_EPHY_LED, 
								1 << _MASK_GPIO_PURPOSE_OFF_EPHY_LED);
	}
	else if (gpioNum >= 37)
	{
		_gpioSetRegMaskValue(_REG_GPIO_PURPOSE, 
								_MASK_GPIO_PURPOSE_SPI, 
								0 << _MASK_GPIO_PURPOSE_OFF_SPI);
	}
	else if (gpioNum >= 36)
	{
		_gpioSetRegMaskValue(_REG_GPIO_PURPOSE, 
								_MASK_GPIO_PURPOSE_PERST, 
								2 << _MASK_GPIO_PURPOSE_OFF_PERST);
	}
	else if (gpioNum >= 24)
	{
		_gpioSetRegMaskValue(_REG_GPIO_PURPOSE, 
								_MASK_GPIO_PURPOSE_RGMII1, 
								1 << _MASK_GPIO_PURPOSE_OFF_RGMII1);
	}
	else if (gpioNum >= 22)
	{
		_gpioSetRegMaskValue(_REG_GPIO_PURPOSE, 
								_MASK_GPIO_PURPOSE_MDIO, 
								2 << _MASK_GPIO_PURPOSE_OFF_MDIO);
	}
	else if (gpioNum >= 18)
	{
		_gpioSetRegMaskValue(_REG_GPIO_PURPOSE, 
								_MASK_GPIO_PURPOSE_PA, 
								1 << _MASK_GPIO_PURPOSE_OFF_PA);
	}
	else if (gpioNum >= 17)
	{
		_gpioSetRegMaskValue(_REG_GPIO_PURPOSE, 
								_MASK_GPIO_PURPOSE_WDT, 
								2 << _MASK_GPIO_PURPOSE_OFF_WDT);
	}
	else if (gpioNum >= 15)
	{
		_gpioSetRegMaskValue(_REG_GPIO_PURPOSE, 
								_MASK_GPIO_PURPOSE_UARTL, 
								1 << _MASK_GPIO_PURPOSE_OFF_UARTL);
	}
	else if (gpioNum >= 7)
	{
		_gpioSetRegMaskValue(_REG_GPIO_PURPOSE, 
								_MASK_GPIO_PURPOSE_UARTF, 
								7 << _MASK_GPIO_PURPOSE_OFF_UARTF);
	}
	else if (gpioNum >= 3)
	{
		_gpioSetRegMaskValue(_REG_GPIO_PURPOSE, 
								_MASK_GPIO_PURPOSE_SPI, 
								1 << _MASK_GPIO_PURPOSE_OFF_SPI);
		_gpioSetRegMaskValue(_REG_GPIO_PURPOSE, 
								_MASK_GPIO_PURPOSE_SPI_REFCLK0, 
								1 << _MASK_GPIO_PURPOSE_OFF_SPI_REFCLK0);
	}
	else if (gpioNum >= 1)
	{
		_gpioSetRegMaskValue(_REG_GPIO_PURPOSE, 
								_MASK_GPIO_PURPOSE_I2C, 
								1 << _MASK_GPIO_PURPOSE_OFF_I2C);
	}
	else 
	{
		/* Port 0 need no setting */
	}
}


static void _gpioSetDirectionOut(unsigned long gpioNum)
{
	_gpioSetPortAsGpioMode(gpioNum);
	//_motor_print("Set register %X bit %X, GPIO %d.\n", _gpioDirReg(gpioNum), _gpioOffsetNum(gpioNum), gpioNum);
	_REG_SET_BITS(_gpioDirReg(gpioNum), _gpioOffsetNum(gpioNum));
}


static void _gpioSetDirectionIn(unsigned long gpioNum)
{
	_gpioSetPortAsGpioMode(gpioNum);
	//_motor_print("Set register %X bit %X, GPIO %d.\n", _gpioDirReg(gpioNum), _gpioOffsetNum(gpioNum), gpioNum);
	_REG_CLR_BITS(_gpioDirReg(gpioNum), _gpioOffsetNum(gpioNum));
}


static void _gpioSetPinLow(unsigned long gpioNum)
{
	_REG_CLR_BITS(_gpioOutValReg(gpioNum), _gpioOffsetNum(gpioNum));
}


static void _gpioSetPinHigh(unsigned long gpioNum)
{
	_REG_SET_BITS(_gpioOutValReg(gpioNum), _gpioOffsetNum(gpioNum));
}


static BOOL _gpioIsHigh(int gpioNum)
{
	_gpioSetDirectionIn(gpioNum);

	if (_REG_GET_VAL(_gpioInValReg(gpioNum)) & (1 << _gpioOffsetNum(gpioNum)))
	{
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

#endif




/******** motor drive operations ********/
#define __MOTOR_DRIVE_OPERATIONS
#ifdef __MOTOR_DRIVE_OPERATIONS

BOOL _motorReachNegativeEnd(unsigned long index)
{
	if (_motorIfConf[index].GpioPinNegativeMax >= 0)
	{
		return _GPIO_REACH_LIMIT(_motorIfConf[index].GpioPinNegativeMax);
	}
	else
	{
		return FALSE;
	}
}


BOOL _motorReachPositiveEnd(unsigned long index)
{
	if (_motorIfConf[index].GpioPinPositiveMax >= 0)
	{
		return _GPIO_REACH_LIMIT(_motorIfConf[index].GpioPinPositiveMax);
	}
	else
	{
		return FALSE;
	}
}


/* When motor reaches negative end, this function SHOULD be called */
static void _motorUpdateStatusWithNegativeEnd(unsigned long index)
{
	_motorIfStatus[index].isBackwardMax = TRUE;
	_motorIfStatus[index].isForwardMax = FALSE;

	if (_motorIfIsNegativeFound[index])
	{
		/**/
		/* (N___X___P) ==> (NN______P) */
		if (_motorIfIsPositiveFound[index])
		{
			_motor_print("(N___X___P) ==> (NN______P) \n");
			_motorIfStatus[index].position = _motorIfStatus[index].negativeMax;
		}
		/**/
		/* (N___X___?) ==> (XX______?) */
		else
		{
			_motor_print("(N___X___?) ==> (XX______?) \n");
			_motorIfStatus[index].negativeMax = _motorIfStatus[index].position;
		}
	}
	else
	{
		/**/
		/* (?___X___P) ==> (XX______P) */
		if (_motorIfIsPositiveFound[index])
		{
			signed long diff;
			diff = _motorIfStatus[index].positiveMax - _motorIfStatus[index].position;
			_motor_print("(?___X___P) ==> (XX______P) diff %ld \n", diff);

			if (diff & 0x1)		/* odd */
			{
				_motorIfStatus[index].negativeMax = 0 - (diff >> 1);
				_motorIfStatus[index].positiveMax = (diff >> 1) + 1;
			}
			else				/* even */
			{
				_motorIfStatus[index].negativeMax = 0 - (diff >> 1);
				_motorIfStatus[index].positiveMax = (diff >> 1);
			}

			_motorIfStatus[index].position = _motorIfStatus[index].negativeMax;
		}
		/**/
		/* (?___X___?) ==> (XX______?) */
		else
		{
			_motor_print("(?___X___?) ==> (XX______?) \n");
			_motorIfStatus[index].negativeMax = _motorIfStatus[index].position;
		}

		/**/
		_motorIfIsNegativeFound[index] = TRUE;
	}
	
	_motorIfStatus[index].isCenterFound = _motorIfIsNegativeFound[index] & _motorIfIsPositiveFound[index];
	return;
}


/* When motoe reaches positive end, this function SHOULD be called */
static void _motorUpdateStatusWithPositiveEnd(unsigned long index)
{
	_motorIfStatus[index].isBackwardMax = FALSE;
	_motorIfStatus[index].isForwardMax = TRUE;

	if (_motorIfIsPositiveFound[index])
	{
		/**/
		/* (N___X___P) ==> (N______PP) */
		if (_motorIfIsNegativeFound[index])
		{
			_motor_print("(N___X___P) ==> (N______PP) \n");
			_motorIfStatus[index].position = _motorIfStatus[index].positiveMax;
		}
		/**/
		/* (?___X___P) ==> (?______XX) */
		else
		{
			_motor_print("(?___X___P) ==> (?______XX) \n");
			_motorIfStatus[index].positiveMax = _motorIfStatus[index].position;
		}
	}
	else
	{
		/**/
		/* (N___X___?) ==> (N______XX) */
		if (_motorIfIsNegativeFound[index])
		{
			signed long diff;
			diff = _motorIfStatus[index].position - _motorIfStatus[index].negativeMax;
			_motor_print("(N___X___?) ==> (N______XX), diff %ld(%ld - %ld) \n", diff, _motorIfStatus[index].position, _motorIfStatus[index].negativeMax);

			if (diff & 0x1)		/* odd */
			{
				_motorIfStatus[index].negativeMax = 0 - (diff >> 1);
				_motorIfStatus[index].positiveMax = (diff >> 1) + 1;
			}
			else				/* even */
			{
				_motorIfStatus[index].negativeMax = 0 - (diff >> 1);
				_motorIfStatus[index].positiveMax = (diff >> 1);
			}

			_motorIfStatus[index].position = _motorIfStatus[index].positiveMax;
		}
		/**/
		/* (?___X___?) ==> (?______XX) */
		else
		{
			_motor_print("(?___X___?) ==> (?______XX) \n");
			_motorIfStatus[index].positiveMax = _motorIfStatus[index].position;
		}

		/**/
		_motorIfIsPositiveFound[index] = TRUE;
	}
	
	_motorIfStatus[index].isCenterFound = _motorIfIsNegativeFound[index] & _motorIfIsPositiveFound[index];
	return;
}


void _motorSetDrivePinsDirOut(unsigned long index)
{
	if (index >= CFG_4_PHASE_MOTOR_COUNT)
	{}
	else if (FALSE == _motorIfStatus[index].isInitialized)
	{}
	else
	{
		_gpioSetDirectionOut(_motorIfConf[index].GpioPinA);
		_gpioSetDirectionOut(_motorIfConf[index].GpioPinB);
		_gpioSetDirectionOut(_motorIfConf[index].GpioPinC);
		_gpioSetDirectionOut(_motorIfConf[index].GpioPinD);
	}
}


void _motorSetLimitPinsDirIn(unsigned long index)
{
	if (index >= CFG_4_PHASE_MOTOR_COUNT)
	{}
	else if (FALSE == _motorIfStatus[index].isInitialized)
	{}
	else
	{
		if ((_motorIfConf[index].GpioPinNegativeMax >= 0) &&
			(_motorIfConf[index].GpioPinPositiveMax >= 0))
		{
			_gpioSetDirectionIn(_motorIfConf[index].GpioPinNegativeMax);
			_gpioSetDirectionIn(_motorIfConf[index].GpioPinPositiveMax);
		}
		else
		{}
	}
}

void _motorSetAllStop(unsigned long index)
{
	if (index >= CFG_4_PHASE_MOTOR_COUNT)
	{}
	else if (FALSE == _motorIfStatus[index].isInitialized)
	{}
	else
	{
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinA);
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinB);
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinC);
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinD);
	}
}

#if _CFG_STOP_ALL_PORTS_WHEN_DELAYED
void _motorSetAllStopInDegradedSpeed(unsigned long index)
{
	return _motorSetAllStop(index);
}
#else
#define _motorSetAllStopInDegradedSpeed(x)		// As nothing
#endif


void _motorSetPhaseA_1000(unsigned long index)
{
	if (index >= CFG_4_PHASE_MOTOR_COUNT)
	{}
	else if (FALSE == _motorIfStatus[index].isInitialized)
	{}
	else
	{
		_GPIO_SET_PIN_XCTA(_motorIfConf[index].GpioPinA);
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinB);
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinC);
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinD);
	}
}


void _motorSetPhaseB_1200(unsigned long index)
{
	if (index >= CFG_4_PHASE_MOTOR_COUNT)
	{}
	else if (FALSE == _motorIfStatus[index].isInitialized)
	{}
	else
	{
		_GPIO_SET_PIN_XCTA(_motorIfConf[index].GpioPinA);
		_GPIO_SET_PIN_XCTA(_motorIfConf[index].GpioPinB); 
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinC);
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinD);
	}
}


void _motorSetPhaseC_0200(unsigned long index)
{
	if (index >= CFG_4_PHASE_MOTOR_COUNT)
	{}
	else if (FALSE == _motorIfStatus[index].isInitialized)
	{}
	else
	{
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinA);
		_GPIO_SET_PIN_XCTA(_motorIfConf[index].GpioPinB);
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinC);
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinD);
	}
}


void _motorSetPhaseD_0230(unsigned long index)
{
	if (index >= CFG_4_PHASE_MOTOR_COUNT)
	{}
	else if (FALSE == _motorIfStatus[index].isInitialized)
	{}
	else
	{
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinA);
		_GPIO_SET_PIN_XCTA(_motorIfConf[index].GpioPinB);
		_GPIO_SET_PIN_XCTA(_motorIfConf[index].GpioPinC); 
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinD);
	}
}


void _motorSetPhaseE_0030(unsigned long index)
{
	if (index >= CFG_4_PHASE_MOTOR_COUNT)
	{}
	else if (FALSE == _motorIfStatus[index].isInitialized)
	{}
	else
	{
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinA);
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinB);
		_GPIO_SET_PIN_XCTA(_motorIfConf[index].GpioPinC);
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinD);
	}
}


void _motorSetPhaseF_0034(unsigned long index)
{
	if (index >= CFG_4_PHASE_MOTOR_COUNT)
	{}
	else if (FALSE == _motorIfStatus[index].isInitialized)
	{}
	else
	{
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinA);
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinB);
		_GPIO_SET_PIN_XCTA(_motorIfConf[index].GpioPinC);
		_GPIO_SET_PIN_XCTA(_motorIfConf[index].GpioPinD); 
	}
}


void _motorSetPhaseG_0004(unsigned long index)
{
	if (index >= CFG_4_PHASE_MOTOR_COUNT)
	{}
	else if (FALSE == _motorIfStatus[index].isInitialized)
	{}
	else
	{
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinA);
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinB);
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinC);
		_GPIO_SET_PIN_XCTA(_motorIfConf[index].GpioPinD);
	}
}


void _motorSetPhaseH_1004(unsigned long index)
{
	if (index >= CFG_4_PHASE_MOTOR_COUNT)
	{}
	else if (FALSE == _motorIfStatus[index].isInitialized)
	{}
	else
	{
		_GPIO_SET_PIN_XCTA(_motorIfConf[index].GpioPinA); 
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinB);
		_GPIO_SET_PIN_IDLE(_motorIfConf[index].GpioPinC);
		_GPIO_SET_PIN_XCTA(_motorIfConf[index].GpioPinD);
	}
}




static void _motorStepForward(unsigned long index)
{
	if (index >= CFG_4_PHASE_MOTOR_COUNT)
	{}
	else if (FALSE == _motorIfStatus[index].isInitialized)
	{}
	else
	{
		_motorIfStatus[index].position ++;
		_motorIfStatus[index].isBackwardMax = FALSE;
	
		switch(_motorIfStatus[index].phase)
		{
			case MotorPhase_0_1000:
				_motorSetPhaseB_1200(index);
				_motorIfStatus[index].phase = MotorPhase_1_1200;
				break;

			case MotorPhase_1_1200:
				_motorSetPhaseC_0200(index);
				_motorIfStatus[index].phase = MotorPhase_2_0200;
				break;

			case MotorPhase_2_0200:
				_motorSetPhaseD_0230(index);
				_motorIfStatus[index].phase = MotorPhase_3_0230;
				break;

			case MotorPhase_3_0230:
				_motorSetPhaseE_0030(index);
				_motorIfStatus[index].phase = MotorPhase_4_0030;
				break;

			case MotorPhase_4_0030:
				_motorSetPhaseF_0034(index);
				_motorIfStatus[index].phase = MotorPhase_5_0034;
				break;

			case MotorPhase_5_0034:
				_motorSetPhaseG_0004(index);
				_motorIfStatus[index].phase = MotorPhase_6_0004;
				break;

			case MotorPhase_6_0004:
				_motorSetPhaseH_1004(index);
				_motorIfStatus[index].phase = MotorPhase_7_1004;
				break;

			case MotorPhase_7_1004:
				_motorSetPhaseA_1000(index);
				_motorIfStatus[index].phase = MotorPhase_0_1000;
				break;
				
			default:
				break;
		}
	}
}



static void _motorStepBackward(unsigned long index)
{
	if (index >= CFG_4_PHASE_MOTOR_COUNT)
	{}
	else if (FALSE == _motorIfStatus[index].isInitialized)
	{}
	else
	{
		_motorIfStatus[index].position --;
		_motorIfStatus[index].isForwardMax = FALSE;
	
		switch(_motorIfStatus[index].phase)
		{
			case MotorPhase_0_1000:
				_motorSetPhaseH_1004(index);
				_motorIfStatus[index].phase = MotorPhase_7_1004;
				break;

			case MotorPhase_1_1200:
				_motorSetPhaseA_1000(index);
				_motorIfStatus[index].phase = MotorPhase_0_1000;
				break;

			case MotorPhase_2_0200:
				_motorSetPhaseB_1200(index);
				_motorIfStatus[index].phase = MotorPhase_1_1200;
				break;

			case MotorPhase_3_0230:
				_motorSetPhaseC_0200(index);
				_motorIfStatus[index].phase = MotorPhase_2_0200;
				break;

			case MotorPhase_4_0030:
				_motorSetPhaseD_0230(index);
				_motorIfStatus[index].phase = MotorPhase_3_0230;
				break;

			case MotorPhase_5_0034:
				_motorSetPhaseE_0030(index);
				_motorIfStatus[index].phase = MotorPhase_4_0030;
				break;

			case MotorPhase_6_0004:
				_motorSetPhaseF_0034(index);
				_motorIfStatus[index].phase = MotorPhase_5_0034;
				break;

			case MotorPhase_7_1004:
				_motorSetPhaseG_0004(index);
				_motorIfStatus[index].phase = MotorPhase_6_0004;
				break;
				
			default:
				break;
		}
	}
}



static void _motorDoTimer(unsigned long lasttime)
{
	BOOL shouldRunNextLoop = FALSE;
	BOOL shouldTriggerWaitQueue = FALSE;
	unsigned long index = 0;
	
	/****/
	/* LOCK */
	_LOCK();		/* ---LOCK--- */


	/****/
	/* examine all ports and run them */
	for (index = 0; index < CFG_4_PHASE_MOTOR_COUNT; index++)
	{
		if (FALSE == _motorIfStatus[index].isInitialized)
		{}
		else
		{
			/**/
			/**** forever positive running ****/
			if (TP_MOTOR_Param_PositiveMax == _motorStepRequirement[index])
			{
				/**/
				shouldRunNextLoop = TRUE;
				_motorSpeedDivCountDown[index] --;
				_motorIfStatus[index].isRunning = TRUE;
				_motorIfStatus[index].isForward = TRUE;

				/**/
				if (_motorSpeedDivCountDown[index] <= 0)
				{
					if (_motorReachPositiveEnd(index))
					{
						_motorUpdateStatusWithPositiveEnd(index);
						_motorSetAllStop(index);
						
						shouldTriggerWaitQueue = TRUE;
						_motorStepRequirement[index] = 0;
						_motorIfStatus[index].isRunning = FALSE;
						_motor_print("Motor %d stopped.\n", index);
					}
					else
					{
						_motorStepForward(index);
						_motorSpeedDivCountDown[index] = _motorIfStatus[index].speedDivBy;
					}
				}
				else
				{
					_motorSetAllStopInDegradedSpeed(index);
				}
			}
			/**/
			/**** forever negative running ****/
			else if (TP_MOTOR_Param_NegativeMax == _motorStepRequirement[index])
			{
				/**/
				shouldRunNextLoop = TRUE;
				_motorSpeedDivCountDown[index] --;
				_motorIfStatus[index].isRunning = TRUE;
				_motorIfStatus[index].isForward = FALSE;
				
				/**/
				if (_motorSpeedDivCountDown[index] <= 0)
				{
					if (_motorReachNegativeEnd(index))
					{
						_motorUpdateStatusWithNegativeEnd(index);
						_motorSetAllStop(index);
						
						shouldTriggerWaitQueue = TRUE;
						_motorStepRequirement[index] = 0;
						_motorIfStatus[index].isRunning = FALSE;
						_motor_print("Motor %d stopped.\n", index);
					}
					else
					{
						_motorStepBackward(index);
						_motorSpeedDivCountDown[index] = _motorIfStatus[index].speedDivBy;
					}
				}
				else
				{
					_motorSetAllStopInDegradedSpeed(index);
				}
			}
			/**/
			/**** limited positive running ****/
			else if (_motorStepRequirement[index] > 0)
			{
				/**/
				shouldRunNextLoop = TRUE;
				_motorSpeedDivCountDown[index] --;
				_motorIfStatus[index].isRunning = TRUE;
				_motorIfStatus[index].isForward = TRUE;

				/**/
				if (_motorSpeedDivCountDown[index] <= 0)
				{
					if (_motorReachPositiveEnd(index))
					{
						_motorUpdateStatusWithPositiveEnd(index);
						_motorSetAllStop(index);
						
						shouldTriggerWaitQueue = TRUE;
						_motorStepRequirement[index] = 0;
						_motorIfStatus[index].isRunning = FALSE;
						_motor_print("Motor %d stopped.\n", index);
					}
					else
					{
						_motorStepRequirement[index] --;
						_motorSpeedDivCountDown[index] = _motorIfStatus[index].speedDivBy;
						_motorStepForward(index);
					}
				}
				else
				{
					_motorSetAllStopInDegradedSpeed(index);
				}
			}
			/**/
			/**** limited negative running ****/
			else if (_motorStepRequirement[index] < 0)
			{
				/**/
				shouldRunNextLoop = TRUE;
				_motorSpeedDivCountDown[index] --;
				_motorIfStatus[index].isRunning = TRUE;
				_motorIfStatus[index].isForward = FALSE;
				
				/**/
				if (_motorSpeedDivCountDown[index] <= 0)
				{
					if (_motorReachNegativeEnd(index))
					{
						_motorUpdateStatusWithNegativeEnd(index);
						_motorSetAllStop(index);
						
						shouldTriggerWaitQueue = TRUE;
						_motorStepRequirement[index] = 0;
						_motorIfStatus[index].isRunning = FALSE;
						_motor_print("Motor %d stopped.\n", index);
					}
					else
					{
						_motorStepRequirement[index] ++;
						_motorSpeedDivCountDown[index] = _motorIfStatus[index].speedDivBy;
						_motorStepBackward(index);
					}
				}
				else
				{
					_motorSetAllStopInDegradedSpeed(index);
				}
			}
			/**/
			/**** no running required ****/
			else
			{
				_motorSetAllStop(index);

				if (_motorIfStatus[index].isRunning)
				{
					shouldTriggerWaitQueue = TRUE;
					_motorIfStatus[index].isRunning = FALSE;
					_motor_print("Motor %d stopped.\n", index);
				}
			}
		}
	}


	/****/
	/* prepare for next step */
	_UNLOCK();		/* --UNLOCK-- */
	
	if (shouldRunNextLoop)
	{
		init_timer(&_tpMotorTimer);
		_tpMotorTimer.expires = jiffies + (HZ / 1000);
		add_timer(&_tpMotorTimer);
	}
	else
	{
		_isTimerRunning = FALSE;
	}


	if (shouldTriggerWaitQueue)
	{
		_isAnyMotorStopped = TRUE;
		wake_up_interruptible(&_motorStopQueue);
	}
	

	/****/
	/* ends */
}


void _motorStartTimer(void)
{
	if (_isTimerRunning)
	{
		/* do nothing */
	}
	else
	{
		_isTimerRunning = TRUE;
		init_timer(&_tpMotorTimer);
		_tpMotorTimer.function = _motorDoTimer;
		_tpMotorTimer.expires = jiffies + (HZ / 1000);
		add_timer(&_tpMotorTimer);
	}
}

#endif



/******** private functions for ioctl() ********/
#define __PRIVATE_FUNCTIONS_FOR_IOCTL
#ifdef __PRIVATE_FUNCTIONS_FOR_IOCTL
static int _MotorInitPinNumbers(TP_4PhaseMotorConfig_st *conf)
{
	TP_4PhaseMotorConfig_st confCopy;
	unsigned long index;
	int ret = 0;

	if (NULL == conf)
	{
		return EINVAL;
	}
	else
	{
		copy_from_user(&confCopy, conf, sizeof(confCopy));
		index = confCopy.MotorIndex;

		/****/
		/* check motor index */
		if (index >= CFG_4_PHASE_MOTOR_COUNT)
		{
			ret = ECHRNG;
		}

		/****/
		/* check if port initialized */
		if (0 == ret)
		{
			if (_motorIfStatus[index].isInitialized)
			{
				ret = EACCES;
			}
		}

		/****/
		/* check parameters */
		/* drive pins */
		if ((confCopy.GpioPinA >= 0) && (confCopy.GpioPinA <= TO_MOTOR_GPIO_NUM_MAX) &&
			(confCopy.GpioPinB >= 0) && (confCopy.GpioPinB <= TO_MOTOR_GPIO_NUM_MAX) &&
			(confCopy.GpioPinC >= 0) && (confCopy.GpioPinC <= TO_MOTOR_GPIO_NUM_MAX) &&
			(confCopy.GpioPinD >= 0) && (confCopy.GpioPinD <= TO_MOTOR_GPIO_NUM_MAX))
		{}
		else
		{
			ret = EINVAL;
		}

		/* limit pins */
		if ((-1 == confCopy.GpioPinNegativeMax) &&
			(-1 == confCopy.GpioPinPositiveMax))
		{
			/* no limit */
		}
		else if ((confCopy.GpioPinNegativeMax >= 0) && 
					(confCopy.GpioPinNegativeMax <= TO_MOTOR_GPIO_NUM_MAX) &&
					(confCopy.GpioPinPositiveMax >= 0) && 
					(confCopy.GpioPinPositiveMax <= TO_MOTOR_GPIO_NUM_MAX))
		{
			/* OK */
		}
		else
		{
			ret = EINVAL;
		}

		/****/
		/* configure motor port status */
		if (0 == ret)
		{
			memcpy(&(_motorIfConf[index]), &confCopy, sizeof(TP_4PhaseMotorConfig_st));
			_motorSetDrivePinsDirOut(index);
			_motorSetLimitPinsDirIn(index);

			_motorIfStatus[index].MotorIndex 		= index;
			_motorIfStatus[index].isInitialized 	= TRUE;
			_motorIfStatus[index].isRunning 		= FALSE;
			_motorIfStatus[index].isForward 		= FALSE;
			_motorIfStatus[index].isCenterFound	= FALSE;
			_motorIfStatus[index].isForwardMax	= TRUE;
			_motorIfStatus[index].isBackwardMax	= TRUE;
			_motorIfStatus[index].position		= 0;
			_motorIfStatus[index].phase			= MotorPhase_7_1004;
			_motorIfStatus[index].negativeMax 	= TP_MOTOR_Param_NegativeMax;
			_motorIfStatus[index].positiveMax 	= TP_MOTOR_Param_PositiveMax;

			_motorStepRequirement[index] = 0;
		}

		_motor_print("Motor %d initialized.\n", index);
		return ret;
	}
}


static int _MotorReadPinNumbers(TP_4PhaseMotorConfig_st *conf)
{
	unsigned long index;
	int ret = 0;

	if (NULL == conf)
	{
		ret = EINVAL;
	}


	/****/
	/* check index */
	if (0 == ret)
	{
		index = conf->MotorIndex;

		if (index >= CFG_4_PHASE_MOTOR_COUNT)
		{
			ret = ECHRNG;
		}
	}

	/****/
	/* get status */
	if (0 == ret)
	{
		copy_to_user(conf, &(_motorIfConf[index]), sizeof(*conf));
	}


	/****/
	/* return */
	return ret;
}


static int _MotorReadMotorStatus(TP_4PhaseMotorStatus_st *pStatus)
{
	unsigned long index;
	int ret = 0;

	TP_4PhaseMotorStatus_st status;

	if (NULL == pStatus)
	{
		ret = EINVAL;
	}

	/****/
	/* check index */
	if (0 == ret)
	{
		copy_from_user(&status, pStatus, sizeof(status));

		index = status.MotorIndex;

		if (index >= CFG_4_PHASE_MOTOR_COUNT)
		{
			ret = ECHRNG;
		}
	}

	/****/
	/* copy status */
	if (0 == ret)
	{
		copy_to_user(pStatus, &(_motorIfStatus[index]), sizeof(*pStatus));
	}

	/****/
	/* return */
	return ret;
}


static int _MotorSetRunWithStep(TP_4PhaseMotorCommndParam_st *pPara)
{
	unsigned long index;
	int ret = 0;

	TP_4PhaseMotorCommndParam_st para;

	


	if (NULL == pPara)
	{
		return EINVAL;
	}

	/****/
	/* check index and if motor initialized */
	if (0 == ret)
	{
		copy_from_user(&para, pPara, sizeof(para));

		index = para.MotorIndex;

		if (index >= CFG_4_PHASE_MOTOR_COUNT)
		{
			ret = ECHRNG;
		}
		else if (_motorIfStatus[index].isInitialized)
		{
			/* OK */
		}
		else
		{
			ret = EACCES;
		}
	}


	/****/
	/* set motor step */
	if (0 == ret)
	{
		_LOCK();		/* ---LOCK--- */

		_motorStepRequirement[index] = para.parameter;
		_motorSpeedDivCountDown[index] = _motorIfStatus[index].speedDivBy;

		_UNLOCK();		/* --UNLOCK-- */
		

		if (0 == para.parameter)
		{
			_motorSpeedDivCountDown[index] = 0;
		}
		else
		{
			_motorStartTimer();
		}
	}



	/****/
	/* return */
	//_motor_print("Request motor %ld, return status: %d\n", index, ret);
	return ret;
}


static int _MotorSetSpeedDivBy(TP_4PhaseMotorCommndParam_st *pPara)
{
	unsigned long index;
	int ret = 0;
	TP_4PhaseMotorCommndParam_st para;

	if (NULL == pPara)
	{
		return EINVAL;
	}


	/****/
	/* check index and if motor initialized */
	if (0 == ret)
	{
		copy_from_user(&para, pPara, sizeof(para));

		index = para.MotorIndex;

		if (index >= CFG_4_PHASE_MOTOR_COUNT)
		{
			ret = ECHRNG;
		}
		else if (_motorIfStatus[index].isInitialized)
		{
			/* OK */
		}
		else
		{
			ret = EACCES;
		}
	}


	/****/
	/* set motor speed */
	if (0 == ret)
	{
		if (para.parameter >= 1)
		{
			_motorIfStatus[index].speedDivBy = para.parameter;
		}
	}

	/****/
	/* return */
	return ret;
}

#endif



/******** System calls ********/
#define __MOTOR_DRIVE_SYSTEM_CALLS
#ifdef __MOTOR_DRIVE_SYSTEM_CALLS


/**********/
/* ioctl() */
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35))
long tplink_motor_ioctl(struct file *file, unsigned int req, unsigned long arg)
#else
int tplink_motor_ioctl(struct inode *inode, struct file *file, unsigned int req, unsigned long arg)
#endif
{
	int retCopy = 0;
		
	switch (req)
	{
		case TP_MOTOR_WCMD_SetMotorPinNumbers:
			//mutex_lock(&_ioctlMutex);
			retCopy = _MotorInitPinNumbers((TP_4PhaseMotorConfig_st*)arg);
			//mutex_unlock(&_ioctlMutex);
			break;

		case TP_MOTOR_RCMD_GetMotorPinNumbers:
			//mutex_lock(&_ioctlMutex);
			retCopy = _MotorReadPinNumbers((TP_4PhaseMotorConfig_st*)arg);
			//mutex_unlock(&_ioctlMutex);
			break;

		case TP_MOTOR_RCMD_GetMotorStatus:
			//mutex_lock(&_ioctlMutex);
			retCopy = _MotorReadMotorStatus((TP_4PhaseMotorStatus_st*)arg);
			//mutex_unlock(&_ioctlMutex);
			break;

		case TP_MOTOR_WCMD_SetMotorRunWithStep:
			//mutex_lock(&_ioctlMutex);
			retCopy = _MotorSetRunWithStep((TP_4PhaseMotorCommndParam_st*)arg);
			//mutex_unlock(&_ioctlMutex);
			break;

		case TP_MOTOR_WCMD_SetMotorSpeedDivided:
			//mutex_lock(&_ioctlMutex);
			retCopy = _MotorSetSpeedDivBy((TP_4PhaseMotorCommndParam_st*)arg);
			//mutex_unlock(&_ioctlMutex);
			break;
	
		default:
			printk("## MOTOR: Invalid command code: %d.\n", req);
			retCopy = EINVAL;
			break;
	}



	/****/
	/* return */
	return (0 - retCopy);
}



/**********/
/* open() */
int tplink_motor_open(struct inode *inode, struct file *file)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	MOD_INC_USE_COUNT;
#else
	try_module_get(THIS_MODULE);
#endif
	_motor_print("Motor device opened.\n");
	return 0;
}


/**********/
/* close() */
int tplink_motor_release(struct inode *inode, struct file *file)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
	MOD_DEC_USE_COUNT;
#else
	module_put(THIS_MODULE);
#endif
	_motor_print("Motor device released.\n");
	return 0;
}


/**********/
/* poll() */
unsigned int tplink_motor_poll(struct file *file, struct poll_table_struct *wait)
{
	poll_wait(file, &_motorStopQueue, wait);

	if (_isAnyMotorStopped)
	{
		_isAnyMotorStopped = FALSE;
		return (POLLIN | POLLRDNORM);
	}
	else
	{
		return 0;
	}
}



/**********/
/* device configuration */
static struct file_operations _tpMotorFops =
{
	.owner 			= THIS_MODULE,
#if (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35))
	.unlocked_ioctl = tplink_motor_ioctl,
#else
	.ioctl 			= tplink_motor_ioctl,
#endif
	.open 			= tplink_motor_open,
	.release 		= tplink_motor_release,
	.poll 			= tplink_motor_poll,
};


/**********/
/* __init function */
int __init tplink_motor_init(void)
{
	int retCode, tmp;
	BOOL isOK = TRUE;

	retCode = register_chrdev(_tpMotorMajor, _NAME, &_tpMotorFops);

	/******/
	/* register device */
	if (retCode < 0)
	{
		isOK = FALSE;
	}
	else if (0 == _tpMotorMajor)
	{
		_tpMotorMajor = retCode;
	}
	else
	{}

	/******/
	/* check and create device node */
	if (isOK)
	{
		mutex_init(&_motorMutex);
		mutex_init(&_ioctlMutex);
		printk("#### TP-LINK motor module registered OK, device number: %d\n", _tpMotorMajor);
#if _CFG_STOP_ALL_PORTS_WHEN_DELAYED
		printk("#### Motor module runs in discontinuous mode.\n");
#else
		printk("#### Motor module runs in continuous mode.\n");
#endif

		/**********
		 * Comment created by Andrew Chang on 2014-06-30:
		 *     After involking class_create() and device_create() functions, a device
		 * "file" should had been created in /dev directory. However, nothing happened.
		 * I had to give up trying, and use the "mknod" command instead.
		 */
#if 0		
//#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,35)
		struct class *devClass = class_create(THIS_MODULE, _NAME);
		struct device *dev;

		if (IS_ERR(devClass))
		{
			_motor_print("Failed to create device node "_DEV_NAME".\n");
		}
		else
		{
			dev = device_create(devClass, NULL, MKDEV(_tpMotorMajor, 0), NULL, "%s", _DEV_NAME);

			if (IS_ERR(dev))
			{
				_motor_print("Failed to create device node "_DEV_NAME".\n");
			}
			else
			{
				_motor_print("Device node "_DEV_NAME" created.\n");
			}	
		}
		
#endif
	}
	else
	{
		_motor_print("Failed to register TP-LINK motor device, error code: %d\n", retCode);
	}


	/******/
	/* initialize parameters */
	for (tmp = 0; tmp < CFG_4_PHASE_MOTOR_COUNT; tmp++)
	{
		_motorIfConf[tmp].MotorIndex = tmp;
		_motorIfConf[tmp].GpioPinA = -1;
		_motorIfConf[tmp].GpioPinB = -1;
		_motorIfConf[tmp].GpioPinC = -1;
		_motorIfConf[tmp].GpioPinD = -1;
		_motorIfConf[tmp].GpioPinNegativeMax = -1;
		_motorIfConf[tmp].GpioPinPositiveMax = -1;

		_motorIfStatus[tmp].MotorIndex 		= tmp;
		_motorIfStatus[tmp].isInitialized 	= FALSE;
		_motorIfStatus[tmp].isRunning 		= FALSE;
		_motorIfStatus[tmp].isForward 		= FALSE;
		_motorIfStatus[tmp].isCenterFound	= FALSE;
		_motorIfStatus[tmp].isForwardMax	= FALSE;
		_motorIfStatus[tmp].isBackwardMax	= FALSE;
		_motorIfStatus[tmp].position		= 0;
		_motorIfStatus[tmp].phase			= MotorPhase_7_1004;
		_motorIfStatus[tmp].speedDivBy 	= CFG_4_PHASE_MOTOR_SPEED_DIV;
		_motorIfStatus[tmp].negativeMax 	= TP_MOTOR_Param_NegativeMax;
		_motorIfStatus[tmp].positiveMax 	= TP_MOTOR_Param_PositiveMax;

		_motorStepRequirement[tmp] = 0;

		_motorIfIsPositiveFound[tmp] = FALSE;
		_motorIfIsNegativeFound[tmp] = FALSE;
	}


	/******/
	/* return */
	return 0;
}



/**********/
/* __exit function */
void __exit tplink_motor_exit(void)
{
	mutex_destroy(&_motorMutex);
	mutex_destroy(&_ioctlMutex);
	_motor_print("TP-LINK motor device exited.\n");
}



/**********/
/* register init and exit functions */
module_init(tplink_motor_init);
module_exit(tplink_motor_exit);

#endif


