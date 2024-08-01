from app import app
from datetime import datetime
from models import db, User, Event, Ticket, Payment, Category, EventCategory

def seed_data():
    with app.app_context():
        # Drop existing tables and create new ones
        db.drop_all()
        db.create_all()

        # Clear session
        db.session.remove()
                # Create Users with plaintext passwords (only for testing, not for production)
        organizer1 = User(username='janedoe', email='janedoe@example.com', role='organizer')
        organizer1.set_password('securepass')

        organizer2 = User(username='michaelsmith', email='michaelsmith@example.com', role='organizer')
        organizer2.set_password('michaelpass')

        customer1 = User(username='emilybrown', email='emilybrown@example.com', role='customer')
        customer1.set_password('emilypass')

        customer2 = User(username='davidjohnson', email='davidjohnson@example.com', role='customer')
        customer2.set_password('davidpass')

        customer3 = User(username='sarahjones', email='sarahjones@example.com', role='customer')
        customer3.set_password('sarahpass')

        customer4 = User(username='lindaallen', email='lindaallen@example.com', role='customer')
        customer4.set_password('lindapass')

        # db.session.add(admin)
        db.session.add(organizer1)
        db.session.add(organizer2)
        db.session.add(customer1)
        db.session.add(customer2)
        db.session.add(customer3)
        db.session.add(customer4)
            



        # Create Categories
        music_category = Category(name='Music')
        tech_category = Category(name='Technology')

        db.session.add(music_category)
        db.session.add(tech_category)

        # Commit the users and categories
        db.session.commit()

        # Create Events
        event1 = Event(
            title='Music Concert',
            description='A great music concert featuring popular bands.',
            location='Central Park',
            start_time=datetime(2024, 8, 15, 19, 0, 0),
            end_time=datetime(2024, 8, 15, 22, 0, 0),
            organizer_id=organizer1.id,
            total_tickets=500,
            remaining_tickets=500
        )

        event2 = Event(
            title='Tech Conference',
            description='A conference showcasing the latest in technology.',
            location='Tech Center Auditorium',
            start_time=datetime(2024, 9, 10, 9, 0, 0),
            end_time=datetime(2024, 9, 10, 17, 0, 0),
            organizer_id=organizer2.id,
            total_tickets=200,
            remaining_tickets=200
        )

        db.session.add(event1)
        db.session.add(event2)

        # Commit the events
        db.session.commit()

        # Create Event Categories
        event_category1 = EventCategory(event_id=event1.id, category_id=music_category.id)
        event_category2 = EventCategory(event_id=event2.id, category_id=tech_category.id)

        db.session.add(event_category1)
        db.session.add(event_category2)

        # Commit the event categories
        db.session.commit()

        # Create Tickets
        ticket1 = Ticket(
            event_id=event1.id,
            user_id=customer1.id,
            ticket_type='Early Booking',
            price=50.00,
            quantity=2,
            status='pending'
        )

        ticket2 = Ticket(
            event_id=event1.id,
            user_id=customer2.id,
            ticket_type='Regular',
            price=50.00,
            quantity=1,
            status='pending'
        )

        ticket3 = Ticket(
            event_id=event2.id,
            user_id=customer3.id,
            ticket_type='VIP',
            price=100.00,
            quantity=3,
            status='pending'
        )

        ticket4 = Ticket(
            event_id=event2.id,
            user_id=customer4.id,
            ticket_type='Early Bird',
            price=75.00,
            quantity=2,
            status='pending'
        )

        db.session.add(ticket1)
        db.session.add(ticket2)
        db.session.add(ticket3)
        db.session.add(ticket4)

        # Commit the tickets
        db.session.commit()

        # Create Payments
        payment1 = Payment(
            ticket_id=ticket1.id,
            amount=100.00,
            payment_method='MPESA STK',
            payment_status='completed'
        )

        payment2 = Payment(
            ticket_id=ticket2.id,
            amount=50.00,
            payment_method='MPESA STK',
            payment_status='completed'
        )

        payment3 = Payment(
            ticket_id=ticket3.id,
            amount=300.00,
            payment_method='Credit Card',
            payment_status='completed'
        )

        payment4 = Payment(
            ticket_id=ticket4.id,
            amount=150.00,
            payment_method='Credit Card',
            payment_status='completed'
        )

        db.session.add(payment1)
        db.session.add(payment2)
        db.session.add(payment3)
        db.session.add(payment4)

        # Commit all changes to the database
        db.session.commit()

if __name__ == '__main__':
    seed_data()
    print("Database seeded!")
