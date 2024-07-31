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

        # Create Users
        admin = User(username='admin', email='admin@example.com', _password_hash='hashedpassword', role='admin')
        organizer = User(username='organizer', email='organizer@example.com', _password_hash='hashedpassword', role='organizer')
        customer = User(username='customer', email='customer@example.com', _password_hash='hashedpassword', role='customer')

        db.session.add(admin)
        db.session.add(organizer)
        db.session.add(customer)

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
            organizer_id=organizer.id,
            total_tickets=500,
            remaining_tickets=500
        )

        event2 = Event(
            title='Tech Conference',
            description='A conference showcasing the latest in technology.',
            location='Tech Center Auditorium',
            start_time=datetime(2024, 9, 10, 9, 0, 0),
            end_time=datetime(2024, 9, 10, 17, 0, 0),
            organizer_id=organizer.id,
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
            user_id=customer.id,
            ticket_type='Early Bird',
            price=50.00,
            quantity=2,
            status='purchased'
        )

        ticket2 = Ticket(
            event_id=event2.id,
            user_id=customer.id,
            ticket_type='Regular',
            price=100.00,
            quantity=1,
            status='purchased'
        )

        db.session.add(ticket1)
        db.session.add(ticket2)

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
            amount=100.00,
            payment_method='MPESA STK',
            payment_status='completed'
        )

        db.session.add(payment1)
        db.session.add(payment2)

        # Commit all changes to the database
        db.session.commit()

if __name__ == '__main__':
    seed_data()
    print("Database seeded!")
