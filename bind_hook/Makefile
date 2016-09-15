

bind_hook.so: bind_hook.c
	gcc -Wall -Werror -shared -fPIC -o $@ -D_GNU_SOURCE $< -ldl

clean:
	rm -f bind_hook.so

.PHONY: clean
