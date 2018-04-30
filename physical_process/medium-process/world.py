import pygame

#Define colors
BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
GREEN = (0, 255, 0)
RED = (255, 0, 0)
BLUE = (0, 0, 255)

pygame.init()

size = (700, 500)
screen = pygame.display.set_mode(size)

pygame.display.set_caption("Test")

done = False

clock = pygame.time.Clock()

def draw_approvisionning(screen, color, pos, width, left = True ):
    pygame.draw.rect(screen, color, pos, width)
    if left:
        xs = pos[0] + pos[2]
        ys = pos[1] + pos[3] - 30
        rect_width = 25
        rect_length = 10

    else:
        rect_width = 25
        rect_length = 10
        xs = pos[0] - rect_width
        ys = pos[1] + pos[3] - 30

    pygame.draw.rect(screen, color, [xs, ys, rect_width, rect_length], width)

    if left:
        draw_valve(screen, color, [xs+rect_width, ys, 15,15], width)    
        draw_valve_end(screen, color, [xs+rect_width, ys, 15,15], width, left)
    else:
        draw_valve(screen, color, [xs-15, ys, 15, 15], width)
        draw_valve_end(screen, color, [xs-15, ys, 15, 15], width, left)
    

def draw_valve(screen, color, pos, width):
    pygame.draw.ellipse(screen, color, pos,width)
    px =  [pos[0] + (pos[2]/2) , pos[1]]
    py =  [pos[0], pos[1] - 3] 
    pz =  [pos[0] + pos[2], pos[1] - 3]
    pygame.draw.polygon(screen, BLUE, [px, py, pz], width)
    px =  [pos[0] + (pos[2]/2) , pos[1] + pos[3]]
    py =  [pos[0], (pos[1]+pos[3] + 3)] 
    pz =  [pos[0] + pos[2], (pos[1] + pos[3] + 3)]
    pygame.draw.polygon(screen, BLUE, [px, py, pz], width)

def draw_valve_end(screen, color, pos, width, left):
    if left:
        px =  [pos[0] + pos[2], pos[1]]
        py =  [pos[0] + 20, pos[1]] 
        pz =  [py[0], py[1] + 20]
    else:
        px = [pos[0], pos[1]]
        py = [pos[0] - 20, pos[1]]
        pz = [py[0], py[1] + 20]

    pygame.draw.line(screen, BLUE, px, py, width)
    pygame.draw.line(screen, BLUE, py, pz, width)

    if left:
        x = [px[0], px[1] + 5]
        y = [py[0] - 5, py[1] + 5]
        z = [pz[0] - 5, pz[1]]
    else:
        x = [px[0], px[1] + 5]
        y = [py[0] + 5, py[1] + 5]
        z = [pz[0] + 5, pz[1]]

    pygame.draw.line(screen, BLUE, x, y, width)
    pygame.draw.line(screen, BLUE, y, z, width)
    


while not done:
    for event in pygame.event.get():
        if event.type == pygame.QUIT:
            done = True
    # Game logic

    # Screen clearing code goes here

    screen.fill(WHITE)

    # Drawing code 

    #a1
    draw_approvisionning(screen, BLUE, [10,5,40,80], 2)
    #a2
    draw_approvisionning(screen, BLUE, [200,5,40,80], 2, False)
    #t1
    draw_approvisionning(screen, BLUE, [90,90,40,80], 2)
    #s1
    draw_approvisionning(screen, BLUE, [150, 180, 40, 80],2)
    #s2
    draw_approvisionning(screen, BLUE, [210, 270, 40, 80],2)
    #s3
    draw_approvisionning(screen, BLUE, [270, 360, 40, 80],2)



    # Update screen
    pygame.display.flip()
    # Limit to 60 frames per second
    clock.tick(60)

pygame.quit()
