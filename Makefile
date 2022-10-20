NAME = ft_traceroute
SRC = ./src/ft_traceroute.c
OBJ	= $(SRC:.c=.o)
# CFLAGS	=-Wall -Wextra -Werror
CFLAGS	=
P_HEADER = ./inc/ft_traceroute.h
FT_LIB = ./libft/libft.a

all: $(FT_LIB) $(NAME)

$(FT_LIB): 
	@make -C  ./libft

$(OBJ): $(P_HEADER)
	gcc $(CFLAGS) -c $(SRC) -o $(OBJ)
	

$(NAME): $(OBJ)
	gcc $(CFLAGS) -o $(NAME) $(OBJ) $(FT_LIB)


clean:
	@make -C  ./libft clean
	-rm $(OBJ)

fclean: clean
	@make -C  ./libft fclean
	-rm $(NAME)

re: fclean all
