// SPDX-License-Identifier: GPL-2.0
/*
 * Small user-facing test helper for Lenovo Y700 AW86937 haptics.
 *
 * It intentionally uses the standard Linux input force-feedback API, so it
 * tests the same public interface that normal Linux software should use.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define Y700_HAPTIC_TEST_MAX_DURATION_MS 10000

struct motor {
	const char *name;
	char event_path[PATH_MAX];
	int fd;
	int effect_id;
};

static struct motor motors[] = {
	{ .name = "aw86937-haptics-left", .fd = -1, .effect_id = -1 },
	{ .name = "aw86937-haptics-right", .fd = -1, .effect_id = -1 },
};

static int read_first_line(const char *path, char *buf, size_t len)
{
	FILE *f;
	size_t n;

	f = fopen(path, "r");
	if (!f)
		return -1;

	if (!fgets(buf, len, f)) {
		fclose(f);
		return -1;
	}

	fclose(f);
	n = strlen(buf);
	while (n && (buf[n - 1] == '\n' || buf[n - 1] == '\r'))
		buf[--n] = '\0';

	return 0;
}

static int find_motor_event(struct motor *motor)
{
	DIR *dir;
	struct dirent *de;
	char name_path[PATH_MAX];
	char name[128];

	dir = opendir("/sys/class/input");
	if (!dir)
		return -1;

	while ((de = readdir(dir))) {
		if (strncmp(de->d_name, "event", 5))
			continue;

		snprintf(name_path, sizeof(name_path),
			 "/sys/class/input/%s/device/name", de->d_name);
		if (read_first_line(name_path, name, sizeof(name)))
			continue;
		if (strcmp(name, motor->name))
			continue;

		snprintf(motor->event_path, sizeof(motor->event_path),
			 "/dev/input/%s", de->d_name);
		closedir(dir);
		return 0;
	}

	closedir(dir);
	return -1;
}

static int emit_ff(int fd, int code, int value)
{
	struct input_event ev;

	memset(&ev, 0, sizeof(ev));
	ev.type = EV_FF;
	ev.code = code;
	ev.value = value;

	return write(fd, &ev, sizeof(ev)) == sizeof(ev) ? 0 : -1;
}

static int prepare_motor(struct motor *motor, unsigned int duration_ms,
			 unsigned int magnitude, unsigned int effect_type,
			 unsigned int period_ms)
{
	struct ff_effect effect;

	if (find_motor_event(motor)) {
		fprintf(stderr, "missing input event for %s\n", motor->name);
		return -1;
	}

	motor->fd = open(motor->event_path, O_RDWR);
	if (motor->fd < 0) {
		fprintf(stderr, "open %s failed: %s\n", motor->event_path,
			strerror(errno));
		return -1;
	}

	memset(&effect, 0, sizeof(effect));
	effect.id = -1;
	if (effect_type == FF_PERIODIC) {
		effect.type = FF_PERIODIC;
		effect.u.periodic.waveform = FF_SINE;
		effect.u.periodic.period = period_ms ? period_ms : 6;
		effect.u.periodic.magnitude = magnitude * 0x7fffU / 0xffffU;
	} else if (effect_type == FF_CONSTANT) {
		effect.type = FF_CONSTANT;
		effect.u.constant.level = magnitude * 0x7fffU / 0xffffU;
	} else {
		effect.type = FF_RUMBLE;
		effect.u.rumble.strong_magnitude = magnitude;
	}
	effect.replay.length = duration_ms;

	if (ioctl(motor->fd, EVIOCSFF, &effect) < 0) {
		fprintf(stderr, "EVIOCSFF %s failed: %s\n", motor->event_path,
			strerror(errno));
		close(motor->fd);
		motor->fd = -1;
		return -1;
	}

	motor->effect_id = effect.id;
	return 0;
}

static void cleanup_motor(struct motor *motor)
{
	if (motor->fd < 0)
		return;

	if (motor->effect_id >= 0) {
		emit_ff(motor->fd, motor->effect_id, 0);
		ioctl(motor->fd, EVIOCRMFF, motor->effect_id);
	}

	close(motor->fd);
	motor->fd = -1;
	motor->effect_id = -1;
}

static int play_selected_periodic(int mask, unsigned int duration_ms,
				  unsigned int magnitude, unsigned int effect_type,
				  unsigned int period_ms);

static int play_selected(int mask, unsigned int duration_ms,
			 unsigned int magnitude)
{
	return play_selected_periodic(mask, duration_ms, magnitude, FF_RUMBLE, 6);
}

static int play_selected_periodic(int mask, unsigned int duration_ms,
				  unsigned int magnitude, unsigned int effect_type,
				  unsigned int period_ms)
{
	int i;
	int ret = 0;

	if (duration_ms < 5)
		duration_ms = 5;
	if (duration_ms > Y700_HAPTIC_TEST_MAX_DURATION_MS)
		duration_ms = Y700_HAPTIC_TEST_MAX_DURATION_MS;
	if (magnitude > 65535)
		magnitude = 65535;

	for (i = 0; i < 2; i++) {
		if (!(mask & (1 << i)))
			continue;
		if (prepare_motor(&motors[i], duration_ms, magnitude,
				  effect_type, period_ms))
			ret = -1;
	}

	if (ret)
		goto out;

	for (i = 0; i < 2; i++) {
		if ((mask & (1 << i)) && motors[i].fd >= 0)
			emit_ff(motors[i].fd, motors[i].effect_id, 1);
	}

	usleep((duration_ms + 30) * 1000);

out:
	for (i = 0; i < 2; i++)
		cleanup_motor(&motors[i]);

	return ret;
}

static int play_constant(unsigned int duration_ms, unsigned int magnitude,
			 unsigned int repeats, unsigned int gap_ms)
{
	unsigned int i;

	for (i = 0; i < repeats; i++) {
		if (play_selected_periodic(3, duration_ms, magnitude, FF_CONSTANT, 6))
			return -1;
		if (i + 1 < repeats)
			usleep(gap_ms * 1000);
	}

	return 0;
}

static void usage(const char *argv0)
{
	fprintf(stderr,
		"usage:\n"
		"  %s left|right|both [duration_ms] [magnitude] [repeats] [gap_ms]\n"
		"  %s constant [duration_ms] [magnitude] [repeats] [gap_ms]\n"
		"  %s periodic [duration_ms] [magnitude] [period_ms] [repeats] [gap_ms]\n"
		"\n"
		"examples:\n"
		"  %s both 13 65535 5 65\n"
		"  %s constant 18 65535 5 65\n"
		"  %s periodic 45 65535 6 2 100\n"
		"  %s both 5000 65535 1 65\n"
		"  %s both 45 62000 3 120\n",
		argv0, argv0, argv0, argv0,
		argv0, argv0, argv0, argv0);
}

int main(int argc, char **argv)
{
	unsigned int duration_ms = 25;
	unsigned int magnitude = 65535;
	unsigned int repeats = 1;
	unsigned int gap_ms = 80;
	int mask;
	unsigned int i;

	if (argc < 2) {
		usage(argv[0]);
		return 2;
	}

	if (!strcmp(argv[1], "left")) {
		mask = 1 << 0;
	} else if (!strcmp(argv[1], "right")) {
		mask = 1 << 1;
	} else if (!strcmp(argv[1], "both")) {
		mask = (1 << 0) | (1 << 1);
	} else if (!strcmp(argv[1], "periodic")) {
		duration_ms = argc > 2 ? strtoul(argv[2], NULL, 0) : 45;
		magnitude = argc > 3 ? strtoul(argv[3], NULL, 0) : 65535;
		unsigned int period_ms = argc > 4 ? strtoul(argv[4], NULL, 0) : 6;
		repeats = argc > 5 ? strtoul(argv[5], NULL, 0) : 2;
		gap_ms = argc > 6 ? strtoul(argv[6], NULL, 0) : 100;
		for (i = 0; i < repeats; i++) {
			if (play_selected_periodic(3, duration_ms, magnitude, FF_PERIODIC,
						   period_ms))
				return 1;
			if (i + 1 < repeats)
				usleep(gap_ms * 1000);
		}
		return 0;
	} else if (!strcmp(argv[1], "constant")) {
		duration_ms = argc > 2 ? strtoul(argv[2], NULL, 0) : 18;
		magnitude = argc > 3 ? strtoul(argv[3], NULL, 0) : 65535;
		repeats = argc > 4 ? strtoul(argv[4], NULL, 0) : 5;
		gap_ms = argc > 5 ? strtoul(argv[5], NULL, 0) : 65;
		return play_constant(duration_ms, magnitude, repeats, gap_ms) ? 1 : 0;
	} else {
		usage(argv[0]);
		return 2;
	}

	if (argc > 2)
		duration_ms = strtoul(argv[2], NULL, 0);
	if (argc > 3)
		magnitude = strtoul(argv[3], NULL, 0);
	if (argc > 4)
		repeats = strtoul(argv[4], NULL, 0);
	if (argc > 5)
		gap_ms = strtoul(argv[5], NULL, 0);

	for (i = 0; i < repeats; i++) {
		if (play_selected(mask, duration_ms, magnitude))
			return 1;
		if (i + 1 < repeats)
			usleep(gap_ms * 1000);
	}

	return 0;
}
