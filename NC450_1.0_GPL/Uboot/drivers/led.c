
#include <common.h>


//#include <asm/io.h>
/**
 *
 *	FIle		led.c	
 *	Description	This file is used for the LED controlling.
 *				Here, we light the red LED to indicate that device is booting.
 *
 *	Author		zj	16/10/2013
 *	
 **/

#include <rt_mmap.h>
#include <configs/rt2880.h>

#define RT2880_REG(x)		(*((volatile u32 *)(x)))
#define MYRT2880_REG(x)		(*((volatile u32 *)(x)))

#define RALINK_LED_STATUS_ADDR		PHYS_FLASH_START+0x31300
#define RALINK_LED_STATUS_OFF		0xcf	
#define RALINK_LED_STATUS_ON		0xef



#define RALINK_GPIO_LED_SYS_RED		42
#define RALINK_GPIO_LED_SYS_GREEN	44
#define RALINK_GPIO_LED_WPS_GREEN	40

#define RALINK_REG_PIO7140DIR	(RALINK_PIO_BASE+0x74)

void light_green_led(void)
{
	u32 pio7140_val = RT2880_REG(RALINK_REG_PIO7140DIR);
	pio7140_val |= 1<<(RALINK_GPIO_LED_SYS_GREEN - 40);
	RT2880_REG(RALINK_REG_PIO7140DIR) = pio7140_val;
}

void light_red_led(void)
{
	u32 pio7140_val = RT2880_REG(RALINK_REG_PIO7140DIR);
	pio7140_val |= 1<<(RALINK_GPIO_LED_SYS_RED - 40);
	RT2880_REG(RALINK_REG_PIO7140DIR) = pio7140_val;
}
void light_off(void)
{
	u32 pio7140_val = RT2880_REG(RALINK_REG_PIO7140DIR);
	pio7140_val &= 0;
	RT2880_REG(RALINK_REG_PIO7140DIR) = pio7140_val;	
}



void led(void)
{

	//set gpio to led mode
	u32 gpio_val = RT2880_REG(RT2880_GPIOMODE_REG);
	gpio_val |= 1<<15;						
	RT2880_REG(RT2880_GPIOMODE_REG) = gpio_val;


	u8 ledStatus = MYRT2880_REG(RALINK_LED_STATUS_ADDR);

	printf("\bLed status : 0x%02x\n", ledStatus);

	if( ledStatus == RALINK_LED_STATUS_ON )
	{
		light_red_led();
	}


	light_red_led();


	u32 pio7140_val = RT2880_REG(RALINK_REG_PIO7140DIR);

	printf("led control---------\n");
	printf("0x%08x:0x%08x\n", RT2880_GPIOMODE_REG, gpio_val);;
	printf("0x%08x:0x%08x\n", RALINK_REG_PIO7140DIR, pio7140_val);


	printf("after write\n");
	printf("0x%08x:0x%08x\n", RT2880_GPIOMODE_REG, gpio_val);;
	printf("0x%08x:0x%08x\n", RALINK_REG_PIO7140DIR, pio7140_val);



}
