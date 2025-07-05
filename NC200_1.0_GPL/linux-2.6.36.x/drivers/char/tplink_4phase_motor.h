/**********************************************************************************
	Copyright (C), 2002-2014, TP-LINK TECHNOLOGIES CO., LTD.

	File name:	tplink_4phase-motor.h
	Version:	0.0.1
	Author:		Andrew Chang (or Zhang Min, the same guy)
	
	Discription:
 			This is the driver to access GPIO based 4-phase motor. It provide simple
 		interface to initialize and control motor.
	
	History:
		2014-06-30: File created.
		
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
	2. laplacezhang@126.com		(personal Email)

 **********************************************************************************/

#ifndef	__TPLINK_4PHASE_MOTOR_H__
#define	__TPLINK_4PHASE_MOTOR_H__


#define	CFG_4_PHASE_MOTOR_COUNT		(4)
#define	TO_MOTOR_GPIO_NUM_MAX		(72)
#define	CFG_4_PHASE_MOTOR_SPEED_DIV	(1)
#define	CFG_4_PHASE_MOTOR_SPEED_DIV_MIN		(10)


#ifndef	BOOL
#define	BOOL	int
#define	FALSE	(0)
#define	TRUE	(!FALSE)
#endif

#define	TP_MOTOR_Param_PositiveMax		(0x7fffffff)
#define	TP_MOTOR_Param_NegativeMax		(0x80000000)


typedef struct {
	unsigned long	MotorIndex;
	long			GpioPinA;
	long			GpioPinB;
	long			GpioPinC;
	long			GpioPinD;
	long			GpioPinNegativeMax;
	long			GpioPinPositiveMax;
} TP_4PhaseMotorConfig_st;


typedef enum {
	MotorPhase_0_1000	= 0,
	MotorPhase_1_1200,
	MotorPhase_2_0200,
	MotorPhase_3_0230,
	MotorPhase_4_0030,
	MotorPhase_5_0034,
	MotorPhase_6_0004,
	MotorPhase_7_1004
} TP_4PhaseMotorPhase_t;


typedef struct {
	unsigned long 	MotorIndex;
	BOOL 			isInitialized;
	BOOL 			isRunning;
	BOOL 			isForward;		/* Forward: 1000 -> 1200 -> 0200 -> ... */
	BOOL 			isCenterFound;
	BOOL 			isForwardMax;
	BOOL 			isBackwardMax;
	signed long 	position;	/* if "isCenterFound" is false, this value may not be corrrect */
	TP_4PhaseMotorPhase_t phase;
	unsigned long 	speedDivBy;
	signed long 	negativeMax;
	signed long 	positiveMax;
} TP_4PhaseMotorStatus_st;	/* Values in this structure is read-only */


typedef struct {
	unsigned long 	MotorIndex;
	long 			parameter;
} TP_4PhaseMotorCommndParam_st;




/**********/
/* ioctl commands */
#define	TP_MOTOR_CMD_READ_MASK		(0x0000)
#define	TP_MOTOR_CMD_WRITE_MASK		(0x0100)

/* command naming rule:
 *     "TP_MOTOR" + command type + command name
 * Command type: WCMD (write command), RCMD (read command)
 */

/* Goal: Set motor pin numbers. 
 * Para: TP_4PhaseMotorConfig_st*
 * Ret:  0 if set OK
 *       -1 if failed
 * Errno:
 *     ECHRNG: GPIO number out of range
 *     EACCES: Motor port has already been initialized
 *     EINVAL: Motor not set propertly
 * Disp:
 *     Assign pin numbers to motor port. Assign motor index, GPIO pin numbers
 * in the TP_4PhaseMotorConfig_st structure. This can ONLY be set once.
 */
#define	TP_MOTOR_WCMD_SetMotorPinNumbers		(TP_MOTOR_CMD_READ_MASK | 0x01)


/* Goal: Get motor pin numbers. 
 * Para: TP_4PhaseMotorConfig_st*
 * Ret:  0 if set OK
 *       -1 if failed
 * Errno:
 *     ECHRNG: GPIO number out of range
 *     EACCES: Motor port has not been initialized
 *     EINVAL: Motor index not set propertly
 * Disp:
 *     Read current motor pin number settings. Assign motor index before ioctl.
 */
#define	TP_MOTOR_RCMD_GetMotorPinNumbers		(TP_MOTOR_CMD_WRITE_MASK | 1)


/* Goal: Get motor status. 
 * Para: TP_4PhaseMotorStatus_st*
 * Ret:  0 if set OK
 *       -1 if failed
 * Errno:
 *     ECHRNG: GPIO number out of range
 *     EINVAL: Motor index not set propertly
 * Disp:
 *     Read current motor status. Assign motor index before ioctl.
 */
#define	TP_MOTOR_RCMD_GetMotorStatus			(TP_MOTOR_CMD_READ_MASK | 2)


/* Goal: Make motor start running 
 * Para: TP_4PhaseMotorCommndParam_st*
 * Ret:  0 if set OK
 *       -1 if failed
 * Errno:
 *     ECHRNG: GPIO number out of range
 *     EACCES: Motor port has not been initialized
 * Disp:
 *     Read current motor status. Assign all parameters before ioctl. Use 
 * TP_MOTOR_Param_PositiveMax or TP_MOTOR_Param_NegativeMax to request run till
 * limited.
 */
#define	TP_MOTOR_WCMD_SetMotorRunWithStep		(TP_MOTOR_CMD_WRITE_MASK | 3)


/* Goal: Make motor start running 
 * Para: TP_4PhaseMotorCommndParam_st*
 * Ret:  0 if set OK
 *       -1 if failed
 * Errno:
 *     ECHRNG: GPIO number out of range
 *     EACCES: Motor port has not been initialized
 * Disp:
 *     Set motor speed. The larger he parameter is, the slower the motor is.
 * Parameter should be equal or greater than 1, and less or equal than 10.
 */
#define	TP_MOTOR_WCMD_SetMotorSpeedDivided		(TP_MOTOR_CMD_WRITE_MASK | 4)




#endif		/* End of File */



