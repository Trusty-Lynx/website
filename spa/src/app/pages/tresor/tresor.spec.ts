import { ComponentFixture, TestBed } from '@angular/core/testing';
import { Tresor } from './tresor';

describe('Tresor', () => {
  let component: Tresor;
  let fixture: ComponentFixture<Tresor>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [Tresor],
    }).compileComponents();

    fixture = TestBed.createComponent(Tresor);
    component = fixture.componentInstance;
    await fixture.whenStable();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
